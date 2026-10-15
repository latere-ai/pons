// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/internal/store/postgres"
	"latere.ai/x/pons/internal/store/postgres/pgtest"
	"latere.ai/x/pons/internal/store/storetest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// adapter is one store of a test, with its clock and a dump of every value
// it holds at rest.
type adapter struct {
	st    store.Store
	clock *storetest.Clock
	dump  func(t *testing.T) []byte
}

// both runs fn against a fresh memory store and a fresh Postgres store.
func both(t *testing.T, fn func(t *testing.T, a adapter)) {
	t.Run("memory", func(t *testing.T) {
		clock := storetest.NewClock()
		m := memory.New(memory.Options{Now: clock.Now})
		fn(t, adapter{st: m, clock: clock, dump: func(*testing.T) []byte { return m.Dump() }})
	})
	t.Run("postgres", func(t *testing.T) {
		clock := storetest.NewClock()
		direct, _ := pgtest.Database(t)
		s, err := postgres.Open(context.Background(), direct, postgres.Options{Now: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		fn(t, adapter{st: s, clock: clock, dump: func(t *testing.T) []byte { return dumpPostgres(t, direct) }})
	})
}

// dumpPostgres is every column of every table as the server sends it.
func dumpPostgres(t *testing.T, dsn string) []byte {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	var out bytes.Buffer
	for _, table := range []string{"connectors", "connections", "credentials", "flows", "registrations", "calls", "idempotency_keys"} {
		rows, err := conn.Query(ctx, `SELECT * FROM `+table)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			n++
			for _, v := range rows.RawValues() {
				out.Write(v)
				out.WriteByte('\n')
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&out, "%s: %d rows\n", table, n)
	}
	// The text form as well, in case a column is sent as text.
	for _, table := range []string{"credentials", "flows", "registrations", "connectors"} {
		var text string
		if err := conn.QueryRow(ctx, `SELECT coalesce(string_agg(t::text, E'\n'), '') FROM `+table+` t`).Scan(&text); err != nil {
			t.Fatal(err)
		}
		out.WriteString(text)
	}
	return out.Bytes()
}

// The connection's state moves only along the edges of the diagram, every
// other move is refused, and of two movers from one state one wins, on
// both adapters.
func TestConnectionStateMachine(t *testing.T) {
	both(t, func(t *testing.T, a adapter) { storetest.StateMachine(t, a.st) })
}

// A delete removes the connection, its credential and its flow in one
// transaction.
func TestDeleteRemovesTheCredentialFirst(t *testing.T) {
	both(t, func(t *testing.T, a adapter) { storetest.Delete(t, a.st) })
}

// A confirm or a new key that writes the credential while a refresh is
// claimed wins: the refresh's completion writes nothing.
func TestAReconnectWinsOverARefresh(t *testing.T) {
	both(t, func(t *testing.T, a adapter) { storetest.AReconnectWinsOverARefresh(t, a.st) })
}

// Two creates racing on one idempotency key make one object.
func TestIdempotencyKeyRace(t *testing.T) {
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		var mu sync.Mutex
		var made []string
		var wg sync.WaitGroup
		errs := make([]error, 8)
		start := make(chan struct{})
		for i := range 8 {
			wg.Go(func() {
				<-start
				c := storetest.Connection("alice", fmt.Sprintf("notion-%d", i), store.StateConnected)
				errs[i] = a.st.Tx(ctx, func(tx store.Tx) error {
					// The key is written first, so a second request with the
					// pair waits on it and loses before it makes anything.
					if err := tx.Idempotency().Put(ctx, store.IdempotencyKey{
						Subject: "alice", Key: "one-key", Route: "POST /connections", Status: 201, Object: c.ID,
					}); err != nil {
						return err
					}
					return tx.Connections().Create(ctx, c, 0)
				})
				if errs[i] == nil {
					mu.Lock()
					made = append(made, c.ID)
					mu.Unlock()
				}
			})
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			if err != nil && !errors.Is(err, store.ErrKeyTaken) {
				t.Fatalf("a racing create: %v", err)
			}
		}
		if len(made) != 1 {
			t.Fatalf("%d creates on one key made an object", len(made))
		}
		k, err := a.st.Idempotency().Get(ctx, "alice", "one-key")
		if err != nil {
			t.Fatal(err)
		}
		if k.Object != made[0] || k.Status != 201 {
			t.Fatalf("the key answers %+v, the object made is %s", k, made[0])
		}
		rows, _, err := a.st.Connections().List(ctx, store.Filter{Owners: []string{"alice"}}, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("alice holds %d connections", len(rows))
		}
	})
}

// A canary credential, verifier, pending credential and client secret
// appear in no column of any table of either adapter.
func TestNoPlaintextAtRest(t *testing.T) {
	const canary = "canary-7f3c9e21-pons"
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		s := storetest.Sealer(t, 1)
		c := storetest.Connection("alice", "notion", store.StatePending)
		storetest.Create(t, a.st, c)
		cred := storetest.Credential(t, s, c, store.Secrets{AccessToken: "access-" + canary, RefreshToken: "refresh-" + canary})
		if _, err := a.st.Credentials().Put(ctx, c.ID, cred); err != nil {
			t.Fatal(err)
		}
		f := storetest.Flow(t, s, c, a.clock.Now().Add(time.Hour))
		verifier, err := s.Seal([]byte("verifier-"+canary), store.VerifierBinding(f.ID, c.ID))
		if err != nil {
			t.Fatal(err)
		}
		f.Verifier = verifier
		f.Pending = storetest.Credential(t, s, c, store.Secrets{AccessToken: "pending-" + canary})
		if err := a.st.Flows().Put(ctx, f); err != nil {
			t.Fatal(err)
		}
		key := storetest.Connection("alice", "search", store.StateConnected)
		storetest.Create(t, a.st, key)
		if _, err := a.st.Credentials().Put(ctx, key.ID, storetest.Credential(t, s, key, store.Secrets{Value: "key-" + canary})); err != nil {
			t.Fatal(err)
		}
		secret, err := s.Seal([]byte("secret-"+canary), store.RegistrationBinding("https://auth.example.com", "cb"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.st.Registrations().Put(ctx, store.Registration{
			Issuer: "https://auth.example.com", RedirectURI: "cb", ClientID: "c", Secret: secret,
		}); err != nil {
			t.Fatal(err)
		}
		dump := a.dump(t)
		if !bytes.Contains(dump, []byte(c.ID)) || !bytes.Contains(dump, cred.Sealed.Ciphertext) {
			t.Fatal("the dump does not hold what was stored, so it proves nothing")
		}
		if bytes.Contains(dump, []byte(canary)) {
			t.Fatal("a canary is at rest in the clear")
		}
	})
}

// The client secret of a vouched-for connector is sealed at rest in both
// adapters, opens under its own connector and token endpoint alone, and is
// rewrapped with every other sealed value.
func TestAConnectorsSecretIsSealed(t *testing.T) {
	const canary = "canary-client-secret-5d1e"
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		s := storetest.Sealer(t, 1)
		const endpoint = "https://auth.example.com/token"
		secret, err := s.Seal([]byte(canary), store.ConnectorClientBinding("ctr_vouched", endpoint))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.st.Connectors().Create(ctx, store.Connector{
			ID: "ctr_vouched", Owner: "org", Name: "wiki", Title: "Wiki", Kind: "mcp", URL: "https://wiki.example.com/mcp",
			Auth: []byte(`{"type":"oauth","client":{"id":"wiki-client"}}`), Vouched: true, ClientSecret: secret,
		}, 0); err != nil {
			t.Fatal(err)
		}
		dump := a.dump(t)
		if !bytes.Contains(dump, []byte("ctr_vouched")) || !bytes.Contains(dump, secret.Ciphertext) {
			t.Fatal("the dump does not hold what was stored, so it proves nothing")
		}
		if bytes.Contains(dump, []byte(canary)) {
			t.Fatal("a connector's client secret is at rest in the clear")
		}
		got, err := a.st.Connectors().Get(ctx, "ctr_vouched")
		if err != nil {
			t.Fatal(err)
		}
		plain, err := s.Open(got.ClientSecret, store.ConnectorClientBinding("ctr_vouched", endpoint))
		if err != nil || string(plain) != canary {
			t.Fatalf("the secret does not open under its own binding: %v", err)
		}
		for name, b := range map[string]store.Binding{
			"another connector":      store.ConnectorClientBinding("ctr_other", endpoint),
			"another token endpoint": store.ConnectorClientBinding("ctr_vouched", "https://elsewhere.example.net/token"),
			"a registration":         store.RegistrationBinding("https://auth.example.com", endpoint),
		} {
			if _, err := s.Open(got.ClientSecret, b); !errors.Is(err, store.ErrNotOpened) {
				t.Errorf("the secret opens under %s: %v", name, err)
			}
		}
		rotated := storetest.Sealer(t, 2, 1)
		if n, err := store.Rewrap(ctx, a.st, rotated, store.RewrapBatchSize); err != nil || n != 1 {
			t.Fatalf("the rewrap moved %d: %v", n, err)
		}
		got, err = a.st.Connectors().Get(ctx, "ctr_vouched")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storetest.Sealer(t, 2).Open(got.ClientSecret, store.ConnectorClientBinding("ctr_vouched", endpoint)); err != nil {
			t.Fatalf("the rewrapped secret does not open under the new key: %v", err)
		}
	})
}

// After a key is prepended, the rewrap moves every value of the three
// tables under it, across batches, and keeps every ciphertext byte.
func TestRotationRewrapsEveryValue(t *testing.T) {
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		old := storetest.Sealer(t, 1)
		rotated := storetest.Sealer(t, 2, 1)
		ciphertexts := map[string][]byte{}
		const n = 230
		err := a.st.Tx(ctx, func(tx store.Tx) error {
			for i := range n {
				c := storetest.Connection("alice", fmt.Sprintf("c%03d", i), store.StatePending)
				if err := tx.Connections().Create(ctx, c, 0); err != nil {
					return err
				}
				cred := storetest.Credential(t, old, c, store.Secrets{AccessToken: fmt.Sprintf("access-token-%d", i)})
				if _, err := tx.Credentials().Put(ctx, c.ID, cred); err != nil {
					return err
				}
				ciphertexts[c.ID] = cred.Sealed.Ciphertext
				if i%10 == 0 {
					if err := tx.Flows().Put(ctx, storetest.Flow(t, old, c, a.clock.Now().Add(time.Hour))); err != nil {
						return err
					}
				}
			}
			for i := range 3 {
				secret, err := old.Seal([]byte("client-secret"), store.RegistrationBinding(fmt.Sprintf("https://a%d.example.com", i), "cb"))
				if err != nil {
					return err
				}
				if _, err := tx.Registrations().Put(ctx, store.Registration{
					Issuer: fmt.Sprintf("https://a%d.example.com", i), RedirectURI: "cb", ClientID: "c", Secret: secret,
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		before, err := store.Remaining(ctx, a.st, rotated)
		if err != nil {
			t.Fatal(err)
		}
		if before[store.TableCredentials].NotFirst != n || before[store.TableFlows].NotFirst != 2*(n/10) || before[store.TableRegistrations].NotFirst != 3 {
			t.Fatalf("before the rewrap %v", before)
		}
		moved, err := store.Rewrap(ctx, a.st, rotated, store.RewrapBatchSize)
		if err != nil {
			t.Fatal(err)
		}
		if moved != n+n/10+3 {
			t.Fatalf("the rewrap moved %d rows", moved)
		}
		after, err := store.Remaining(ctx, a.st, rotated)
		if err != nil {
			t.Fatal(err)
		}
		for table, c := range after {
			if c != (store.KeyCount{}) {
				t.Fatalf("%s still holds %+v", table, c)
			}
		}
		first := rotated.Keys().First
		for conn, want := range ciphertexts {
			got, _, err := a.st.Credentials().Get(ctx, conn)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Sealed.Ciphertext, want) || !bytes.Equal(got.Sealed.KeyID, first) {
				t.Fatalf("%s: the ciphertext changed or the key did not", conn)
			}
		}
	})
}

// A refresh that completes while its row is being rewrapped loses no write:
// the rewrap writes the wrap alone, and the refresh's credential is the one
// kept.
func TestRewrapNeverOverwritesARefresh(t *testing.T) {
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		old := storetest.Sealer(t, 1)
		rotated := storetest.Sealer(t, 2, 1)
		c := storetest.Connection("alice", "notion", store.StateConnected)
		storetest.Create(t, a.st, c)
		if _, err := a.st.Credentials().Put(ctx, c.ID, storetest.Credential(t, old, c, store.Secrets{AccessToken: "access-token-1"})); err != nil {
			t.Fatal(err)
		}
		claimed, from, err := a.st.Credentials().ClaimRefresh(ctx, c.ID, 30*time.Second)
		if err != nil || !claimed {
			t.Fatalf("the claim: %t, %v", claimed, err)
		}
		refreshed := storetest.Credential(t, rotated, c, store.Secrets{AccessToken: "access-token-2"})
		done := make(chan error, 1)
		var once sync.Once
		// The refresh completes while the rewrap holds the row: it is
		// started from inside the rewrap and waits for it.
		rewrap := func(s store.Sealed) (store.Sealed, error) {
			once.Do(func() {
				go func() { done <- a.st.Credentials().CompleteRefresh(ctx, c.ID, from, refreshed) }()
				time.Sleep(100 * time.Millisecond)
			})
			return rotated.Rewrap(s)
		}
		if _, err := a.st.Rotation().RewrapBatch(ctx, store.TableCredentials, rotated.Keys(), store.RewrapBatchSize, rewrap); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("the refresh lost to the rewrap: %v", err)
		}
		got, version, err := a.st.Credentials().Get(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if version != from+1 || !bytes.Equal(got.Sealed.Ciphertext, refreshed.Sealed.Ciphertext) {
			t.Fatalf("the refresh's write was overwritten: version %d", version)
		}
		if _, err := rotated.Open(got.Sealed, store.CredentialBinding(c.ID, c.Owner, store.KindOAuth, store.Meta{
			Issuer: "https://auth.example.com", TokenEndpoint: "https://auth.example.com/token",
		}, "")); err != nil {
			t.Fatalf("the stored credential does not open: %v", err)
		}
	})
}

// Records older than the retention are swept in batches and newer ones
// stay; idempotency keys older than 24 hours go too; two replicas sweeping
// at once remove each row once.
func TestRetentionSweep(t *testing.T) {
	both(t, func(t *testing.T, a adapter) {
		ctx := context.Background()
		now := a.clock.Now()
		const retention = 720 * time.Hour
		const old = store.SweepBatch*2 + 150
		c := storetest.Connection("alice", "notion", store.StateConnected)
		var kept []string
		err := a.st.Tx(ctx, func(tx store.Tx) error {
			for i := range old {
				if err := tx.Calls().Insert(ctx, storetest.Call(c, now.Add(-retention-time.Duration(i+1)*time.Second))); err != nil {
					return err
				}
			}
			for i := range 5 {
				call := storetest.Call(c, now.Add(-retention+time.Duration(i+1)*time.Minute))
				kept = append(kept, call.ID)
				if err := tx.Calls().Insert(ctx, call); err != nil {
					return err
				}
			}
			for i, age := range []time.Duration{25 * time.Hour, 48 * time.Hour, time.Hour} {
				if err := tx.Idempotency().Put(ctx, store.IdempotencyKey{Subject: "alice", Key: fmt.Sprintf("k%d", i),
					Route: "POST /connections", Status: 201, Object: id.New(id.Connection), CreatedAt: now.Add(-age)}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		calls, keys := 0, 0
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Go(func() {
				c, k, err := store.Sweep(ctx, a.st, now, retention)
				mu.Lock()
				calls, keys, errs[i] = calls+c, keys+k, err
				mu.Unlock()
			})
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != old || keys != 2 {
			t.Fatalf("two sweepers removed %d records and %d keys, want %d and 2", calls, keys, old)
		}
		rows, _, err := a.st.Calls().List(ctx, c.ID, store.Page{Limit: store.MaxLimit})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(kept) {
			t.Fatalf("%d records left, want %d", len(rows), len(kept))
		}
		if _, err := a.st.Idempotency().Get(ctx, "alice", "k2"); err != nil {
			t.Fatalf("a key younger than a day went: %v", err)
		}
	})
}

// failing is a store whose prunes and rewraps fail.
type failing struct {
	store.Store
	table string
}

var errFailing = errors.New("failing")

func (f failing) Calls() store.Calls             { return failingCalls{f.Store.Calls(), f.table} }
func (f failing) Idempotency() store.Idempotency { return failingKeys{f.Store.Idempotency(), f.table} }
func (f failing) Rotation() store.Rotation       { return failingRotation{} }

type failingCalls struct {
	store.Calls
	table string
}

func (f failingCalls) Prune(ctx context.Context, before time.Time, limit int) (int, error) {
	if f.table == "calls" {
		return 0, errFailing
	}
	return f.Calls.Prune(ctx, before, limit)
}

type failingKeys struct {
	store.Idempotency
	table string
}

func (f failingKeys) Prune(context.Context, time.Time, int) (int, error) { return 0, errFailing }

type failingRotation struct{ store.Rotation }

func (failingRotation) RewrapBatch(context.Context, string, store.KeyIDs, int, func(store.Sealed) (store.Sealed, error)) (int, error) {
	return 0, errFailing
}

// A sweep and a rewrap that fail say which table they were at.
func TestSweepAndRewrapFailures(t *testing.T) {
	ctx := context.Background()
	m := memory.New(memory.Options{})
	for _, table := range []string{"calls", "idempotency"} {
		if _, _, err := store.Sweep(ctx, failing{m, table}, time.Now(), time.Hour); !errors.Is(err, errFailing) {
			t.Errorf("a failing prune of %s: %v", table, err)
		}
	}
	if _, err := store.Rewrap(ctx, failing{Store: m}, storetest.Sealer(t, 2, 1), 10); !errors.Is(err, errFailing) {
		t.Errorf("a failing rewrap: %v", err)
	}
}
