// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/postgres"
	"latere.ai/x/pons/internal/store/postgres/migrations"
	"latere.ai/x/pons/internal/store/postgres/pgtest"
	"latere.ai/x/pons/internal/store/storetest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// Postgres passes the one suite on a direct connection.
func TestPostgresStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T, now func() time.Time) store.Store {
		return pgtest.Open(t, false, postgres.Options{Now: now})
	})
}

// Postgres passes the one suite through a transaction-mode pooler, which
// keeps no session state between two statements.
func TestPostgresStoreThroughAPooler(t *testing.T) {
	storetest.Run(t, func(t *testing.T, now func() time.Time) store.Store {
		return pgtest.Open(t, true, postgres.Options{Now: now, MaxConns: 4})
	})
}

// A schema ahead of the binary and a dirty migration each stop the start,
// naming the version; Open refuses a schema at another version than its
// own, and the errors name no part of the URL.
func TestSchemaGuards(t *testing.T) {
	ctx := context.Background()
	highest, err := migrations.Highest()
	if err != nil {
		t.Fatal(err)
	}

	direct, _ := pgtest.Database(t)
	if err := postgres.Migrate(ctx, direct); err != nil {
		t.Fatalf("migrating twice: %v", err)
	}
	if err := pgtest.Exec(ctx, direct, `UPDATE schema_migrations SET version = $1`, int64(highest+1)); err != nil {
		t.Fatal(err)
	}
	err = postgres.Migrate(ctx, direct)
	ahead, carried := fmt.Sprintf("version %d", highest+1), fmt.Sprintf("carries %d", highest)
	if err == nil || !strings.Contains(err.Error(), ahead) || !strings.Contains(err.Error(), carried) {
		t.Fatalf("a schema ahead of the binary: %v", err)
	}
	if _, err := postgres.Open(ctx, direct, postgres.Options{}); err == nil || !strings.Contains(err.Error(), ahead) {
		t.Fatalf("opening a schema ahead of the binary: %v", err)
	}

	dirty, _ := pgtest.Database(t)
	if err := pgtest.Exec(ctx, dirty, `UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatal(err)
	}
	err = postgres.Migrate(ctx, dirty)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", highest)) {
		t.Fatalf("a dirty migration: %v", err)
	}
	if _, err := postgres.Open(ctx, dirty, postgres.Options{}); err == nil || !strings.Contains(err.Error(), "dirty: true") {
		t.Fatalf("opening a dirty schema: %v", err)
	}

	fresh := pgtest.OnDatabase(t, direct, "postgres")
	if _, err := postgres.Open(ctx, fresh, postgres.Options{}); err == nil || !strings.Contains(err.Error(), "version 0") {
		t.Fatalf("opening a database with no schema: %v", err)
	}

	const secret = "s3cret-password"
	unreachable := "postgres://pons:" + secret + "@127.0.0.1:1/pons?sslmode=disable&connect_timeout=2"
	short, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for name, err := range map[string]error{
		"migrate": postgres.Migrate(short, unreachable),
		"open":    func() error { _, err := postgres.Open(short, unreachable, postgres.Options{}); return err }(),
	} {
		if !errors.Is(err, postgres.ErrUnreachable) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s of an unreachable database: %v", name, err)
		}
	}
	for _, bad := range []string{"mysql://pons@db.example.com/pons", "://"} {
		if err := postgres.Migrate(ctx, bad); err == nil || strings.Contains(err.Error(), "db.example.com") {
			t.Errorf("migrating %q: %v", bad, err)
		}
		if _, err := postgres.Open(ctx, bad, postgres.Options{}); err == nil {
			t.Errorf("opening %q was accepted", bad)
		}
	}
}

// The readiness probe answers while the database does, and fails once it
// is closed.
func TestReady(t *testing.T) {
	ctx := context.Background()
	direct, _ := pgtest.Database(t)
	s, err := postgres.Open(ctx, direct+"&pool_max_conns=2", postgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); !errors.Is(err, postgres.ErrUnreachable) {
		t.Fatalf("a closed store is ready: %v", err)
	}
}

// The highest migration is read from the files' numbers.
func TestHighestOf(t *testing.T) {
	got, err := migrations.HighestOf(fstest.MapFS{
		"000001_a.up.sql": {}, "000003_b.up.sql": {}, "README": {},
	})
	if err != nil || got != 3 {
		t.Fatalf("HighestOf = %d, %v", got, err)
	}
	if _, err := migrations.HighestOf(fstest.MapFS{"x_a.up.sql": {}}); err == nil {
		t.Fatal("a migration that does not start with a number was read")
	}
	if _, err := migrations.HighestOf(fstest.MapFS{}); err == nil {
		t.Fatal("no migration at all was read")
	}
}

// Every method answers an error, and none panics, once the pool is closed:
// a statement that fails is returned and never read as a row.
func TestEveryMethodFailsOnAClosedPool(t *testing.T) {
	ctx := context.Background()
	s := pgtest.Open(t, false, postgres.Options{})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	sealer := storetest.Sealer(t, 2, 1)
	c := storetest.Connection("alice", "notion", store.StateConnected)
	cred := storetest.Credential(t, sealer, c, store.Secrets{AccessToken: "access-token"})
	flow := storetest.Flow(t, sealer, c, time.Now())
	errs := map[string]error{}
	add := func(name string, err error) { errs[name] = err }
	add("tx", s.Tx(ctx, func(store.Tx) error { return nil }))
	add("connector create", s.Connectors().Create(ctx, store.Connector{ID: "ctr_x", Owner: "a", Name: "n"}, 0))
	add("connector create capped", s.Connectors().Create(ctx, store.Connector{ID: "ctr_x", Owner: "a", Name: "n"}, 1))
	add("connector update", s.Connectors().Update(ctx, store.Connector{ID: "ctr_x"}))
	_, err := s.Connectors().Get(ctx, "ctr_x")
	add("connector get", err)
	_, _, err = s.Connectors().List(ctx, []string{"a"}, store.Page{})
	add("connector list", err)
	add("connector delete", s.Connectors().Delete(ctx, "ctr_x"))
	add("connection create", s.Connections().Create(ctx, c, 0))
	add("connection create capped", s.Connections().Create(ctx, c, 1))
	_, err = s.Connections().Get(ctx, c.ID)
	add("connection get", err)
	_, _, err = s.Connections().List(ctx, store.Filter{Owners: []string{"a"}}, store.Page{})
	add("connection list", err)
	add("rename", s.Connections().Rename(ctx, c.ID, "x"))
	add("move", s.Connections().Move(ctx, c.ID, store.StateConnected, store.StatePending, ""))
	add("describe", s.Connections().Describe(ctx, c.ID, store.Account{}))
	add("touch", s.Connections().Touch(ctx, c.ID, time.Now()))
	add("connection delete", s.Connections().Delete(ctx, c.ID))
	_, err = s.Connections().CountByState(ctx)
	add("count", err)
	_, err = s.Connections().InUse(ctx, "notion")
	add("in use", err)
	_, err = s.Connections().CountByConnector(ctx, []string{"notion"})
	add("count by connector", err)
	_, err = s.Credentials().Put(ctx, c.ID, cred)
	add("credential put", err)
	_, _, err = s.Credentials().Get(ctx, c.ID)
	add("credential get", err)
	_, _, err = s.Credentials().ClaimRefresh(ctx, c.ID, time.Second)
	add("claim", err)
	add("complete", s.Credentials().CompleteRefresh(ctx, c.ID, 1, cred))
	add("release", s.Credentials().ReleaseRefresh(ctx, c.ID))
	_, err = s.Credentials().GrantHolders(ctx, store.Grant{Issuer: "i", ClientID: "c", Account: "a"})
	add("grant holders", err)
	add("flow put", s.Flows().Put(ctx, flow))
	_, err = s.Flows().Get(ctx, c.ID)
	add("flow get", err)
	_, err = s.Flows().ByState(ctx, flow.StateHash)
	add("by state", err)
	add("flow delete", s.Flows().Delete(ctx, c.ID))
	_, err = s.Flows().TakeExpired(ctx, time.Now(), 0)
	add("take expired", err)
	_, err = s.Registrations().Put(ctx, store.Registration{Issuer: "i", RedirectURI: "r", ClientID: "c"})
	add("registration put", err)
	_, err = s.Registrations().Get(ctx, "i", "r")
	add("registration get", err)
	add("registration delete", s.Registrations().Delete(ctx, "i", "r"))
	add("call insert", s.Calls().Insert(ctx, storetest.Call(c, time.Now())))
	_, _, err = s.Calls().List(ctx, c.ID, store.Page{})
	add("call list", err)
	_, err = s.Calls().Prune(ctx, time.Now(), 0)
	add("call prune", err)
	add("key put", s.Idempotency().Put(ctx, store.IdempotencyKey{Subject: "a", Key: "k"}))
	_, err = s.Idempotency().Get(ctx, "a", "k")
	add("key get", err)
	_, err = s.Idempotency().Prune(ctx, time.Now(), 0)
	add("key prune", err)
	_, err = s.Rotation().RewrapBatch(ctx, store.TableCredentials, sealer.Keys(), 0, sealer.Rewrap)
	add("rewrap", err)
	_, err = s.Rotation().CountNotFirst(ctx, sealer.Keys())
	add("count not first", err)
	for name, err := range errs {
		if err == nil {
			t.Errorf("%s on a closed pool answered no error", name)
		}
	}
}

// A value that is not JSON never reaches a json column.
func TestJSONIsCheckedBeforeItIsBound(t *testing.T) {
	ctx := context.Background()
	s := pgtest.Open(t, false, postgres.Options{})
	c := storetest.Connection("alice", "notion", store.StatePending)
	storetest.Create(t, s, c)
	bad := store.Connector{ID: "ctr_x", Owner: "a", Name: "n", Hosts: []string{"h.example.com"}}
	for name, x := range map[string]func(*store.Connector){
		"auth":    func(c *store.Connector) { c.Auth = []byte("{") },
		"tools":   func(c *store.Connector) { c.Tools = []byte("{") },
		"sign_in": func(c *store.Connector) { c.SignIn = []byte("{") },
	} {
		b := bad
		x(&b)
		if err := s.Connectors().Create(ctx, b, 0); err == nil {
			t.Errorf("a connector whose %s is not JSON was written", name)
		}
		if err := s.Connectors().Update(ctx, b); err == nil && name != "sign_in" {
			t.Errorf("an edit whose %s is not JSON was written", name)
		}
	}
	f := storetest.Flow(t, storetest.Sealer(t, 1), c, time.Now())
	f.Pending.Meta = []byte("{")
	if err := s.Flows().Put(ctx, f); err == nil {
		t.Error("a flow whose pending meta is not JSON was written")
	}
	if _, err := s.Rotation().RewrapBatch(ctx, "connections", storetest.Sealer(t, 2, 1).Keys(), 0, nil); err == nil {
		t.Error("a table with no sealed values was rewrapped")
	}
}
