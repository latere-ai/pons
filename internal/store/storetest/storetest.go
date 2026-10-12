// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package storetest is the one suite both adapters of the store pass
// (specs/005-store-and-sealing.md): a case per method of every interface,
// and the cases the spec names, Transactions, Names, Cap, Delete, Flows,
// Refresh and Prune among them. An adapter's test hands Run a function that
// opens a fresh, empty store on a clock the suite moves.
package storetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// Clock is a clock a test moves.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock is a clock at a whole second, so a time survives the
// microseconds Postgres keeps.
func NewClock() *Clock { return &Clock{t: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)} }

// Now is the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Add moves the clock.
func (c *Clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Open opens a fresh, empty store whose clock is now.
type Open func(t *testing.T, now func() time.Time) store.Store

// env is what one case runs with.
type env struct {
	st    store.Store
	clock *Clock
}

// Run runs every case against fresh stores open makes.
func Run(t *testing.T, open Open) {
	cases := []struct {
		name string
		run  func(*testing.T, env)
	}{
		{"Connectors", testConnectors},
		{"Connections", testConnections},
		{"Names", testNames},
		{"Cap", testCap},
		{"StateMachine", func(t *testing.T, e env) { StateMachine(t, e.st) }},
		{"Credentials", testCredentials},
		{"Refresh", testRefresh},
		{"Delete", testDelete},
		{"Flows", testFlows},
		{"Registrations", testRegistrations},
		{"Calls", testCalls},
		{"Idempotency", testIdempotency},
		{"Prune", testPrune},
		{"Transactions", testTransactions},
		{"Rotation", testRotation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clock := NewClock()
			c.run(t, env{st: open(t, clock.Now), clock: clock})
		})
	}
}

// Connection is a connection of an owner, by name, in a state a create
// admits.
func Connection(owner, name string, state store.State) store.Connection {
	return store.Connection{
		ID: id.New(id.Connection), Owner: owner, Name: name, Connector: "notion",
		Kind: "mcp", Auth: "oauth", State: state, CreatedBy: owner,
	}
}

// Create inserts connections with no cap, failing the test on an error.
func Create(t testing.TB, st store.Store, cs ...store.Connection) {
	t.Helper()
	for _, c := range cs {
		if err := st.Connections().Create(context.Background(), c, 0); err != nil {
			t.Fatalf("creating %s: %v", c.Name, err)
		}
	}
}

// Credential is a sealed credential of a connection.
func Credential(t testing.TB, s store.Sealer, c store.Connection, secrets store.Secrets) store.SealedCredential {
	t.Helper()
	meta := store.Meta{Issuer: "https://auth.example.com", TokenEndpoint: "https://auth.example.com/token", TokenType: "Bearer"}
	plain, err := secrets.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(plain, store.CredentialBinding(c.ID, c.Owner, store.KindOAuth, meta, ""))
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	return store.SealedCredential{Kind: store.KindOAuth, Meta: m, Sealed: sealed}
}

// Sealer is a sealer over keys made of one repeated byte each, the first
// wrapping.
func Sealer(t testing.TB, bytes ...byte) *store.KeySealer {
	t.Helper()
	keys := make([][store.KeySize]byte, len(bytes))
	for i, b := range bytes {
		for j := range keys[i] {
			keys[i][j] = b
		}
	}
	s, err := store.NewSealer(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// is fails the test when err is not want.
func is(t testing.TB, err, want error) {
	t.Helper()
	if !errors.Is(err, want) && !(err == nil && want == nil) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

// ok fails the test on an error.
func ok(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// sameJSON reports whether two documents mean the same, the empty one
// equal to an empty object.
func sameJSON(a, b json.RawMessage) bool {
	norm := func(r json.RawMessage) any {
		if len(r) == 0 {
			return map[string]any{}
		}
		var v any
		if err := json.Unmarshal(r, &v); err != nil {
			return string(r)
		}
		return v
	}
	return reflect.DeepEqual(norm(a), norm(b))
}

// race runs fn n times at once and answers the errors.
func race(n int, fn func(i int) error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn(i)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

func testConnectors(t *testing.T, e env) {
	ctx := context.Background()
	cs := e.st.Connectors()
	wiki := store.Connector{
		ID: id.New(id.Connector), Owner: "alice", Name: "wiki", Title: "Team wiki", Description: "The wiki.",
		Icon: "https://wiki.example.com/icon.svg", Kind: "mcp", URL: "https://wiki.example.com/mcp",
		Hosts: []string{"wiki.example.com"}, Auth: json.RawMessage(`{"type":"token"}`),
		Tools: json.RawMessage(`{"read_only":["get_*"]}`),
	}
	ok(t, cs.Create(ctx, wiki))
	got, err := cs.Get(ctx, wiki.ID)
	ok(t, err)
	if !got.CreatedAt.Equal(e.clock.Now()) || got.Title != wiki.Title || got.URL != wiki.URL ||
		!slices.Equal(got.Hosts, wiki.Hosts) || !sameJSON(got.Auth, wiki.Auth) || !sameJSON(got.Tools, wiki.Tools) ||
		got.Description != wiki.Description || got.Icon != wiki.Icon || got.Owner != "alice" || got.Kind != "mcp" {
		t.Fatalf("read back %+v", got)
	}
	again := wiki
	again.ID = id.New(id.Connector)
	is(t, cs.Create(ctx, again), store.ErrNameTaken)
	again.Owner = "bob"
	ok(t, cs.Create(ctx, again))
	_, err = cs.Get(ctx, id.New(id.Connector))
	is(t, err, store.ErrNotFound)
	bad := wiki
	bad.ID, bad.Name, bad.Auth = id.New(id.Connector), "bad", json.RawMessage(`{`)
	if err := cs.Create(ctx, bad); err == nil {
		t.Fatal("a connector whose auth is not JSON was created")
	}

	// Paging, newest first, and nothing for no owner.
	var made []string
	for i := range 3 {
		c := wiki
		c.ID, c.Owner, c.Name = id.New(id.Connector), "carol", fmt.Sprintf("c%d", i)
		ok(t, cs.Create(ctx, c))
		made = append(made, c.ID)
	}
	first, next, err := cs.List(ctx, []string{"carol"}, store.Page{Limit: 2})
	ok(t, err)
	if len(first) != 2 || first[0].ID != made[2] || first[1].ID != made[1] || next != made[1] {
		t.Fatalf("first page %v, next %q", first, next)
	}
	rest, next, err := cs.List(ctx, []string{"carol"}, store.Page{Limit: 2, Cursor: next})
	ok(t, err)
	if len(rest) != 1 || rest[0].ID != made[0] || next != "" {
		t.Fatalf("second page %v, next %q", rest, next)
	}
	none, _, err := cs.List(ctx, nil, store.Page{})
	ok(t, err)
	if len(none) != 0 {
		t.Fatalf("a list for no owner answered %d", len(none))
	}
	both, _, err := cs.List(ctx, []string{"alice", "bob"}, store.Page{})
	ok(t, err)
	if len(both) != 2 {
		t.Fatalf("alice and bob hold %d", len(both))
	}

	// A connector in use is not removed.
	is(t, cs.Delete(ctx, id.New(id.Connector)), store.ErrNotFound)
	conn := Connection("alice", "wiki", store.StateConnected)
	conn.Connector = wiki.ID
	Create(t, e.st, conn)
	used, err := e.st.Connections().InUse(ctx, wiki.ID)
	ok(t, err)
	if !used {
		t.Fatal("the connector is not in use")
	}
	is(t, cs.Delete(ctx, wiki.ID), store.ErrInUse)
	ok(t, e.st.Connections().Delete(ctx, conn.ID))
	ok(t, cs.Delete(ctx, wiki.ID))
	_, err = cs.Get(ctx, wiki.ID)
	is(t, err, store.ErrNotFound)
}

func testConnections(t *testing.T, e env) {
	ctx := context.Background()
	cs := e.st.Connections()
	a := Connection("alice", "notion", store.StatePending)
	a.Scopes = []string{"read", "write"}
	a.CreatedBy = "service"
	ok(t, cs.Create(ctx, a, 0))
	got, err := cs.Get(ctx, a.ID)
	ok(t, err)
	now := e.clock.Now()
	if got.Owner != "alice" || got.Name != "notion" || got.Connector != "notion" || got.Kind != "mcp" ||
		got.Auth != "oauth" || got.State != store.StatePending || got.CreatedBy != "service" ||
		!slices.Equal(got.Scopes, a.Scopes) || !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) ||
		!got.LastUsedAt.IsZero() || !got.ExpiresAt.IsZero() || got.Reason != "" || got.Account != "" {
		t.Fatalf("read back %+v", got)
	}
	_, err = cs.Get(ctx, id.New(id.Connection))
	is(t, err, store.ErrNotFound)
	is(t, cs.Create(ctx, Connection("alice", "x", store.StateNeedsReconnect), 0), store.ErrIllegalMove)

	// A list narrowed by owners, connector and state, newest first.
	b := Connection("alice", "github", store.StateConnected)
	b.Connector = "github"
	c := Connection("bob", "notion", store.StateConnected)
	Create(t, e.st, b, c)
	list := func(f store.Filter, p store.Page) []string {
		t.Helper()
		rows, _, err := cs.List(ctx, f, p)
		ok(t, err)
		var ids []string
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return ids
	}
	if got := list(store.Filter{Owners: []string{"alice"}}, store.Page{}); !slices.Equal(got, []string{b.ID, a.ID}) {
		t.Fatalf("alice's list %v", got)
	}
	if got := list(store.Filter{}, store.Page{}); len(got) != 0 {
		t.Fatalf("a list for no owner %v", got)
	}
	if got := list(store.Filter{Owners: []string{"alice", "bob"}, Connector: "notion"}, store.Page{}); !slices.Equal(got, []string{c.ID, a.ID}) {
		t.Fatalf("notion's list %v", got)
	}
	if got := list(store.Filter{Owners: []string{"alice", "bob"}, State: store.StateConnected}, store.Page{Limit: 1}); !slices.Equal(got, []string{c.ID}) {
		t.Fatalf("a connected page %v", got)
	}
	_, next, err := cs.List(ctx, store.Filter{Owners: []string{"alice", "bob"}}, store.Page{Limit: 2})
	ok(t, err)
	if next != b.ID {
		t.Fatalf("next %q, want %q", next, b.ID)
	}
	if got := list(store.Filter{Owners: []string{"alice", "bob"}}, store.Page{Limit: 2, Cursor: next}); !slices.Equal(got, []string{a.ID}) {
		t.Fatalf("the page after %v", got)
	}

	// Rename and describe stamp updated_at.
	e.clock.Add(time.Second)
	ok(t, cs.Rename(ctx, a.ID, "notion-work"))
	is(t, cs.Rename(ctx, id.New(id.Connection), "x"), store.ErrNotFound)
	expires := e.clock.Now().Add(24 * time.Hour)
	ok(t, cs.Describe(ctx, a.ID, store.Account{Account: "alice@example.com", Scopes: []string{"read"}, ExpiresAt: expires}))
	is(t, cs.Describe(ctx, id.New(id.Connection), store.Account{}), store.ErrNotFound)
	got, err = cs.Get(ctx, a.ID)
	ok(t, err)
	if got.Name != "notion-work" || got.Account != "alice@example.com" || !slices.Equal(got.Scopes, []string{"read"}) ||
		!got.ExpiresAt.Equal(expires) || !got.UpdatedAt.Equal(e.clock.Now()) || !got.CreatedAt.Equal(now) {
		t.Fatalf("after a rename and a describe %+v", got)
	}

	// Touch writes only when last_used_at is empty or a minute behind.
	used := func() time.Time {
		t.Helper()
		got, err := cs.Get(ctx, a.ID)
		ok(t, err)
		return got.LastUsedAt
	}
	at := e.clock.Now()
	ok(t, cs.Touch(ctx, a.ID, at))
	ok(t, cs.Touch(ctx, a.ID, at.Add(30*time.Second)))
	ok(t, cs.Touch(ctx, a.ID, at.Add(time.Minute)))
	if !used().Equal(at) {
		t.Fatalf("last_used_at moved within a minute: %v", used())
	}
	ok(t, cs.Touch(ctx, a.ID, at.Add(61*time.Second)))
	if !used().Equal(at.Add(61 * time.Second)) {
		t.Fatalf("last_used_at did not move past a minute: %v", used())
	}
	ok(t, cs.Touch(ctx, id.New(id.Connection), at))

	counts, err := cs.CountByState(ctx)
	ok(t, err)
	if counts[store.StatePending] != 1 || counts[store.StateConnected] != 2 || counts[store.StateNeedsReconnect] != 0 {
		t.Fatalf("counts %v", counts)
	}
	used2, err := cs.InUse(ctx, "nothing")
	ok(t, err)
	if used2 {
		t.Fatal("a connector no connection names is in use")
	}
}

func testNames(t *testing.T, e env) {
	ctx := context.Background()
	cs := e.st.Connections()
	Create(t, e.st, Connection("alice", "notion", store.StateConnected), Connection("bob", "notion", store.StateConnected))
	is(t, cs.Create(ctx, Connection("alice", "notion", store.StatePending), 0), store.ErrNameTaken)
	is(t, cs.Create(ctx, Connection("alice", "notion", store.StatePending), 10), store.ErrNameTaken)
	other := Connection("alice", "notion-work", store.StateConnected)
	Create(t, e.st, other)
	is(t, cs.Rename(ctx, other.ID, "notion"), store.ErrNameTaken)
	ok(t, cs.Rename(ctx, other.ID, "notion-work"))
	ok(t, cs.Rename(ctx, other.ID, "notion-2"))
}

func testCap(t *testing.T, e env) {
	ctx := context.Background()
	cs := e.st.Connections()
	ok(t, cs.Create(ctx, Connection("alice", "a", store.StateConnected), 2))
	ok(t, cs.Create(ctx, Connection("alice", "b", store.StatePending), 2))
	is(t, cs.Create(ctx, Connection("alice", "c", store.StateConnected), 2), store.ErrLimitReached)
	ok(t, cs.Create(ctx, Connection("alice", "c", store.StateConnected), 0))
	ok(t, cs.Create(ctx, Connection("bob", "a", store.StateConnected), 1))

	// 8 creates racing at one remaining place yield one connection.
	errs := race(8, func(i int) error {
		return cs.Create(ctx, Connection("alice", fmt.Sprintf("race-%d", i), store.StateConnected), 4)
	})
	made := 0
	for _, err := range errs {
		switch {
		case err == nil:
			made++
		case !errors.Is(err, store.ErrLimitReached):
			t.Fatalf("a racing create: %v", err)
		}
	}
	if made != 1 {
		t.Fatalf("%d racing creates made a connection at one remaining place", made)
	}
	rows, _, err := cs.List(ctx, store.Filter{Owners: []string{"alice"}}, store.Page{})
	ok(t, err)
	if len(rows) != 4 {
		t.Fatalf("alice holds %d", len(rows))
	}
}

// StateMachine holds a store to the connection's state machine: every edge
// of the diagram moves, every other pair is refused before anything is
// written, a connection no longer in the state a move is from is not moved,
// and of two movers from one state one wins.
func StateMachine(t *testing.T, st store.Store) {
	ctx := context.Background()
	cs := st.Connections()
	states := []store.State{store.StatePending, store.StateConnected, store.StateNeedsReconnect}
	// in makes a connection in a state.
	in := func(s store.State) store.Connection {
		t.Helper()
		start := s
		if s == store.StateNeedsReconnect {
			start = store.StateConnected
		}
		c := Connection("owner", "c-"+id.New(id.Connection)[4:], start)
		Create(t, st, c)
		if s == store.StateNeedsReconnect {
			ok(t, cs.Move(ctx, c.ID, store.StateConnected, store.StateNeedsReconnect, store.ReasonRevoked))
		}
		c.State = s
		return c
	}
	for _, from := range states {
		for _, to := range states {
			c := in(from)
			err := cs.Move(ctx, c.ID, from, to, store.ReasonRevoked)
			got, gerr := cs.Get(ctx, c.ID)
			ok(t, gerr)
			if store.Legal(from, to) {
				if err != nil || got.State != to {
					t.Errorf("%s to %s, an edge: %v, now %s", from, to, err, got.State)
				}
				continue
			}
			if !errors.Is(err, store.ErrIllegalMove) || got.State != from {
				t.Errorf("%s to %s, no edge: %v, now %s", from, to, err, got.State)
			}
		}
	}
	// A move needs the row in its from state, and a row.
	c := in(store.StateConnected)
	is(t, cs.Move(ctx, c.ID, store.StatePending, store.StateConnected, ""), store.ErrStateMoved)
	is(t, cs.Move(ctx, id.New(id.Connection), store.StatePending, store.StateConnected, ""), store.ErrNotFound)

	// The reason: set by a refusal, kept through a reconnect, cleared by a
	// confirm.
	reason := func(want string) {
		t.Helper()
		got, err := cs.Get(ctx, c.ID)
		ok(t, err)
		if got.Reason != want {
			t.Fatalf("reason %q, want %q", got.Reason, want)
		}
	}
	ok(t, cs.Move(ctx, c.ID, store.StateConnected, store.StateNeedsReconnect, store.ReasonRefreshRefused))
	reason(store.ReasonRefreshRefused)
	ok(t, cs.Move(ctx, c.ID, store.StateNeedsReconnect, store.StatePending, ""))
	reason(store.ReasonRefreshRefused)
	ok(t, cs.Move(ctx, c.ID, store.StatePending, store.StatePending, ""))
	reason(store.ReasonRefreshRefused)
	ok(t, cs.Move(ctx, c.ID, store.StatePending, store.StatePending, store.ReasonRevoked))
	reason(store.ReasonRevoked)
	ok(t, cs.Move(ctx, c.ID, store.StatePending, store.StateConnected, store.ReasonRevoked))
	reason("")

	// Of 8 movers from one state, one wins.
	errs := race(8, func(int) error {
		return cs.Move(ctx, c.ID, store.StateConnected, store.StateNeedsReconnect, store.ReasonCredentialRefused)
	})
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrStateMoved):
			t.Fatalf("a racing move: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d movers from one state won", won)
	}
}

func testCredentials(t *testing.T, e env) {
	ctx := context.Background()
	s := Sealer(t, 1)
	c := Connection("alice", "notion", store.StateConnected)
	_, err := e.st.Credentials().Put(ctx, c.ID, Credential(t, s, c, store.Secrets{AccessToken: "access-token-1"}))
	is(t, err, store.ErrNotFound)
	Create(t, e.st, c)
	cred := Credential(t, s, c, store.Secrets{AccessToken: "access-token-1", RefreshToken: "refresh-token-1"})
	v, err := e.st.Credentials().Put(ctx, c.ID, cred)
	ok(t, err)
	if v != 1 {
		t.Fatalf("the first version is %d", v)
	}
	got, version, err := e.st.Credentials().Get(ctx, c.ID)
	ok(t, err)
	if version != 1 || got.Kind != cred.Kind || !sameJSON(got.Meta, cred.Meta) || !reflect.DeepEqual(got.Sealed, cred.Sealed) {
		t.Fatalf("read back %+v", got)
	}
	plain, err := s.Open(got.Sealed, store.CredentialBinding(c.ID, c.Owner, store.KindOAuth, store.Meta{
		Issuer: "https://auth.example.com", TokenEndpoint: "https://auth.example.com/token",
	}, ""))
	ok(t, err)
	secrets, err := store.DecodeSecrets(plain)
	ok(t, err)
	if secrets.AccessToken != "access-token-1" || secrets.RefreshToken != "refresh-token-1" {
		t.Fatalf("opened %+v", secrets)
	}
	v, err = e.st.Credentials().Put(ctx, c.ID, cred)
	ok(t, err)
	if v != 2 {
		t.Fatalf("the second version is %d", v)
	}
	_, _, err = e.st.Credentials().Get(ctx, id.New(id.Connection))
	is(t, err, store.ErrNotFound)
	bad := cred
	bad.Meta = json.RawMessage(`{`)
	if _, err := e.st.Credentials().Put(ctx, c.ID, bad); err == nil {
		t.Fatal("a credential whose meta is not JSON was written")
	}
}

func testRefresh(t *testing.T, e env) {
	ctx := context.Background()
	cr := e.st.Credentials()
	s := Sealer(t, 1)
	c := Connection("alice", "notion", store.StateConnected)
	Create(t, e.st, c)
	_, err := cr.Put(ctx, c.ID, Credential(t, s, c, store.Secrets{AccessToken: "access-token-1"}))
	ok(t, err)

	// Of 16 callers that claim at once, one claims, and each learns the
	// version.
	var mu sync.Mutex
	claims := 0
	errs := race(16, func(int) error {
		claimed, version, err := cr.ClaimRefresh(ctx, c.ID, 30*time.Second)
		if err != nil {
			return err
		}
		if version != 1 {
			return fmt.Errorf("version %d", version)
		}
		if claimed {
			mu.Lock()
			claims++
			mu.Unlock()
		}
		return nil
	})
	for _, err := range errs {
		ok(t, err)
	}
	if claims != 1 {
		t.Fatalf("%d of 16 claimed", claims)
	}
	claim := func(want bool) int64 {
		t.Helper()
		claimed, version, err := cr.ClaimRefresh(ctx, c.ID, 30*time.Second)
		ok(t, err)
		if claimed != want {
			t.Fatalf("claimed %t, want %t", claimed, want)
		}
		return version
	}
	// A lease that lapsed is claimed again.
	e.clock.Add(29 * time.Second)
	claim(false)
	e.clock.Add(time.Second)
	claim(true)
	// A release frees it at once.
	ok(t, cr.ReleaseRefresh(ctx, c.ID))
	claim(true)

	// A completion writes, raises the version and ends the lease; one on a
	// moved version writes nothing.
	next := Credential(t, s, c, store.Secrets{AccessToken: "access-token-2"})
	ok(t, cr.CompleteRefresh(ctx, c.ID, 1, next))
	stale := Credential(t, s, c, store.Secrets{AccessToken: "access-token-stale"})
	is(t, cr.CompleteRefresh(ctx, c.ID, 1, stale), store.ErrVersionMoved)
	got, version, err := cr.Get(ctx, c.ID)
	ok(t, err)
	if version != 2 || !reflect.DeepEqual(got.Sealed, next.Sealed) {
		t.Fatalf("after a completion and a moved one: version %d", version)
	}
	claim(true)

	// Put raises the version and ends the lease.
	v, err := cr.Put(ctx, c.ID, next)
	ok(t, err)
	if v != 3 {
		t.Fatalf("Put wrote version %d", v)
	}
	if got := claim(true); got != 3 {
		t.Fatalf("the claim read version %d", got)
	}

	missing := id.New(id.Connection)
	_, _, err = cr.ClaimRefresh(ctx, missing, time.Second)
	is(t, err, store.ErrNotFound)
	is(t, cr.CompleteRefresh(ctx, missing, 1, next), store.ErrNotFound)
	is(t, cr.ReleaseRefresh(ctx, missing), store.ErrNotFound)
	bad := next
	bad.Meta = json.RawMessage(`{`)
	if err := cr.CompleteRefresh(ctx, c.ID, 3, bad); err == nil {
		t.Fatal("a completion whose meta is not JSON was written")
	}
}

// Delete holds a store to removing a connection, its credential and its
// flow together.
func Delete(t *testing.T, st store.Store) {
	ctx := context.Background()
	s := Sealer(t, 1)
	c := Connection("alice", "deleted-"+id.New(id.Connection)[4:], store.StatePending)
	keep := Connection("alice", "kept-"+id.New(id.Connection)[4:], store.StatePending)
	Create(t, st, c, keep)
	for _, x := range []store.Connection{c, keep} {
		_, err := st.Credentials().Put(ctx, x.ID, Credential(t, s, x, store.Secrets{AccessToken: "access-token-" + x.ID}))
		ok(t, err)
		ok(t, st.Flows().Put(ctx, Flow(t, s, x, time.Now().Add(time.Hour))))
	}
	ok(t, st.Connections().Delete(ctx, c.ID))
	_, err := st.Connections().Get(ctx, c.ID)
	is(t, err, store.ErrNotFound)
	_, _, err = st.Credentials().Get(ctx, c.ID)
	is(t, err, store.ErrNotFound)
	_, err = st.Flows().Get(ctx, c.ID)
	is(t, err, store.ErrNotFound)
	_, _, err = st.Credentials().Get(ctx, keep.ID)
	ok(t, err)
	_, err = st.Flows().Get(ctx, keep.ID)
	ok(t, err)
	is(t, st.Connections().Delete(ctx, c.ID), store.ErrNotFound)
}

func testDelete(t *testing.T, e env) { Delete(t, e.st) }

// AReconnectWinsOverARefresh: a caller claims a refresh, a confirm or a new
// key writes the credential meanwhile, and the completion writes nothing.
func AReconnectWinsOverARefresh(t *testing.T, st store.Store) {
	ctx := context.Background()
	s := Sealer(t, 1)
	c := Connection("alice", "reconnect-"+id.New(id.Connection)[4:], store.StateConnected)
	Create(t, st, c)
	_, err := st.Credentials().Put(ctx, c.ID, Credential(t, s, c, store.Secrets{AccessToken: "access-token-old"}))
	ok(t, err)
	claimed, from, err := st.Credentials().ClaimRefresh(ctx, c.ID, 30*time.Second)
	ok(t, err)
	if !claimed {
		t.Fatal("the refresh was not claimed")
	}
	confirmed := Credential(t, s, c, store.Secrets{AccessToken: "access-token-confirmed"})
	_, err = st.Credentials().Put(ctx, c.ID, confirmed)
	ok(t, err)
	refreshed := Credential(t, s, c, store.Secrets{AccessToken: "access-token-refreshed"})
	is(t, st.Credentials().CompleteRefresh(ctx, c.ID, from, refreshed), store.ErrVersionMoved)
	got, _, err := st.Credentials().Get(ctx, c.ID)
	ok(t, err)
	if !reflect.DeepEqual(got.Sealed, confirmed.Sealed) {
		t.Fatal("the refresh overwrote the reconnect's credential")
	}
}

// Flow is a flow of a connection, expiring at a time, with a sealed
// verifier and a pending credential.
func Flow(t testing.TB, s store.Sealer, c store.Connection, expires time.Time) store.Flow {
	t.Helper()
	f := store.Flow{
		ID: id.New(id.Flow), Connection: c.ID, StateHash: []byte("state-" + c.ID),
		Issuer: "https://auth.example.com", AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint: "https://auth.example.com/token", RevocationEndpoint: "https://auth.example.com/revoke",
		IssParameterSupported: true, ClientID: "https://pons.example.com/v1/client",
		RedirectURI: "https://pons.example.com/v1/callback", Resource: "https://mcp.example.com/mcp",
		Scopes: []string{"read"}, ReturnTo: "https://app.example.com/done", ExpiresAt: expires,
	}
	v, err := s.Seal([]byte("verifier-"+c.ID), store.VerifierBinding(f.ID, c.ID))
	if err != nil {
		t.Fatal(err)
	}
	f.Verifier = v
	f.Pending = Credential(t, s, c, store.Secrets{AccessToken: "pending-" + c.ID})
	f.FinishHash = []byte("finish-" + c.ID)
	return f
}

func sameFlow(a, b store.Flow) bool {
	return a.ID == b.ID && a.Connection == b.Connection && bytes.Equal(a.StateHash, b.StateHash) &&
		a.Issuer == b.Issuer && a.AuthorizationEndpoint == b.AuthorizationEndpoint && a.TokenEndpoint == b.TokenEndpoint &&
		a.RevocationEndpoint == b.RevocationEndpoint && a.IssParameterSupported == b.IssParameterSupported &&
		a.ClientID == b.ClientID && a.RedirectURI == b.RedirectURI && a.Resource == b.Resource &&
		slices.Equal(a.Scopes, b.Scopes) && a.ReturnTo == b.ReturnTo && bytes.Equal(a.FinishHash, b.FinishHash) &&
		reflect.DeepEqual(a.Verifier, b.Verifier) && a.Pending.Kind == b.Pending.Kind &&
		sameJSON(a.Pending.Meta, b.Pending.Meta) && reflect.DeepEqual(a.Pending.Sealed, b.Pending.Sealed) &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}

func testFlows(t *testing.T, e env) {
	ctx := context.Background()
	fs := e.st.Flows()
	s := Sealer(t, 1)
	now := e.clock.Now()
	c := Connection("alice", "notion", store.StatePending)
	is(t, fs.Put(ctx, Flow(t, s, c, now.Add(10*time.Minute))), store.ErrNotFound)
	Create(t, e.st, c)
	f := Flow(t, s, c, now.Add(10*time.Minute))
	ok(t, fs.Put(ctx, f))
	got, err := fs.Get(ctx, c.ID)
	ok(t, err)
	if !sameFlow(got, f) || !got.CreatedAt.Equal(now) {
		t.Fatalf("read back %+v", got)
	}
	got, err = fs.ByState(ctx, f.StateHash)
	ok(t, err)
	if got.ID != f.ID {
		t.Fatalf("by state %s", got.ID)
	}
	_, err = fs.ByState(ctx, nil)
	is(t, err, store.ErrNotFound)

	// A new flow replaces the live one; the callback's flow has no state
	// hash and no pending credential before it.
	replaced := Flow(t, s, c, now.Add(10*time.Minute))
	replaced.StateHash = []byte("state-2-" + c.ID)
	replaced.Pending = store.SealedCredential{}
	replaced.FinishHash = nil
	ok(t, fs.Put(ctx, replaced))
	got, err = fs.Get(ctx, c.ID)
	ok(t, err)
	if !sameFlow(got, replaced) || !got.Pending.Sealed.Zero() {
		t.Fatalf("the replacement %+v", got)
	}
	_, err = fs.ByState(ctx, f.StateHash)
	is(t, err, store.ErrNotFound)
	afterCallback := replaced
	afterCallback.StateHash = nil
	ok(t, fs.Put(ctx, afterCallback))
	_, err = fs.ByState(ctx, replaced.StateHash)
	is(t, err, store.ErrNotFound)
	other := Connection("alice", "other", store.StatePending)
	Create(t, e.st, other)
	clash := Flow(t, s, other, now.Add(time.Minute))
	clash.StateHash = []byte("shared")
	ok(t, fs.Put(ctx, clash))
	clash2 := Flow(t, s, c, now.Add(time.Minute))
	clash2.StateHash = []byte("shared")
	if err := fs.Put(ctx, clash2); err == nil {
		t.Fatal("two flows hold one state hash")
	}
	ok(t, fs.Delete(ctx, c.ID))
	_, err = fs.Get(ctx, c.ID)
	is(t, err, store.ErrNotFound)
	ok(t, fs.Delete(ctx, c.ID))

	// Two sweepers take each expired flow once.
	var expired []string
	for i := range 6 {
		x := Connection("bob", fmt.Sprintf("expired-%d", i), store.StatePending)
		Create(t, e.st, x)
		ok(t, fs.Put(ctx, Flow(t, s, x, now.Add(-time.Minute))))
		expired = append(expired, x.ID)
	}
	live := Connection("bob", "live", store.StatePending)
	Create(t, e.st, live)
	ok(t, fs.Put(ctx, Flow(t, s, live, now.Add(time.Minute))))
	var mu sync.Mutex
	var taken []string
	errs := race(2, func(int) error {
		for {
			batch, err := fs.TakeExpired(ctx, now, 2)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				return nil
			}
			mu.Lock()
			for _, f := range batch {
				taken = append(taken, f.Connection)
			}
			mu.Unlock()
		}
	})
	for _, err := range errs {
		ok(t, err)
	}
	slices.Sort(taken)
	slices.Sort(expired)
	if !slices.Equal(taken, expired) {
		t.Fatalf("taken %v, want each of %v once", taken, expired)
	}
	_, err = fs.Get(ctx, live.ID)
	ok(t, err)
	rest, err := fs.TakeExpired(ctx, now, 0)
	ok(t, err)
	if len(rest) != 0 {
		t.Fatalf("%d left", len(rest))
	}
}

func testRegistrations(t *testing.T, e env) {
	ctx := context.Background()
	rs := e.st.Registrations()
	s := Sealer(t, 1)
	secret, err := s.Seal([]byte("client-secret-1"), store.RegistrationBinding("https://auth.example.com", "https://pons.example.com/v1/callback"))
	ok(t, err)
	r := store.Registration{Issuer: "https://auth.example.com", RedirectURI: "https://pons.example.com/v1/callback",
		ClientID: "client-1", Secret: secret}
	kept, err := rs.Put(ctx, r)
	ok(t, err)
	if kept.ClientID != "client-1" || !reflect.DeepEqual(kept.Secret, secret) || !kept.RegisteredAt.Equal(e.clock.Now()) {
		t.Fatalf("kept %+v", kept)
	}
	second := r
	second.ClientID, second.Secret = "client-2", store.Sealed{}
	kept, err = rs.Put(ctx, second)
	ok(t, err)
	if kept.ClientID != "client-1" {
		t.Fatalf("the second registration replaced the first: %s", kept.ClientID)
	}
	public := store.Registration{Issuer: "https://other.example.com", RedirectURI: r.RedirectURI, ClientID: "public"}
	_, err = rs.Put(ctx, public)
	ok(t, err)
	got, err := rs.Get(ctx, public.Issuer, public.RedirectURI)
	ok(t, err)
	if got.ClientID != "public" || !got.Secret.Zero() {
		t.Fatalf("a public client %+v", got)
	}
	ok(t, rs.Delete(ctx, r.Issuer, r.RedirectURI))
	_, err = rs.Get(ctx, r.Issuer, r.RedirectURI)
	is(t, err, store.ErrNotFound)
	ok(t, rs.Delete(ctx, r.Issuer, r.RedirectURI))
}

// Call is a record of a call through a connection at a time.
func Call(c store.Connection, at time.Time) store.Call {
	return store.Call{
		ID: id.New(id.Call), Connection: c.ID, Owner: c.Owner, Connector: c.Connector, Subject: "caller",
		Session: "session-1", At: at, DurationMS: 12, Method: "tools/call", Tool: "search", Effect: "read",
		Outcome: "ok", Status: 200, BytesIn: 10, BytesOut: 20,
	}
}

func testCalls(t *testing.T, e env) {
	ctx := context.Background()
	cl := e.st.Calls()
	c := Connection("alice", "notion", store.StateConnected)
	now := e.clock.Now()
	first := Call(c, now)
	push := Call(c, now)
	push.Method, push.Tool, push.Refs, push.Status, push.Outcome = "POST", "/git-receive-pack", 3, 0, "upstream_error"
	ok(t, cl.Insert(ctx, first))
	ok(t, cl.Insert(ctx, push))
	if err := cl.Insert(ctx, first); err == nil {
		t.Fatal("a record id was written twice")
	}
	ok(t, cl.Insert(ctx, Call(Connection("bob", "x", store.StateConnected), now)))
	rows, next, err := cl.List(ctx, c.ID, store.Page{Limit: 1})
	ok(t, err)
	if len(rows) != 1 || !reflect.DeepEqual(rows[0], push) || next != push.ID {
		t.Fatalf("the first page %+v, next %q", rows, next)
	}
	rows, next, err = cl.List(ctx, c.ID, store.Page{Cursor: next})
	ok(t, err)
	if len(rows) != 1 || !reflect.DeepEqual(rows[0], first) || next != "" {
		t.Fatalf("the second page %+v, next %q", rows, next)
	}
}

func testIdempotency(t *testing.T, e env) {
	ctx := context.Background()
	ix := e.st.Idempotency()
	k := store.IdempotencyKey{Subject: "alice", Key: "key-1", Route: "POST /connections", Status: 201, Object: "con_1"}
	ok(t, ix.Put(ctx, k))
	is(t, ix.Put(ctx, k), store.ErrKeyTaken)
	other := k
	other.Subject = "bob"
	ok(t, ix.Put(ctx, other))
	got, err := ix.Get(ctx, "alice", "key-1")
	ok(t, err)
	k.CreatedAt = e.clock.Now()
	if got != k {
		t.Fatalf("read back %+v", got)
	}
	_, err = ix.Get(ctx, "alice", "key-2")
	is(t, err, store.ErrNotFound)
}

// testPrune: Prune removes only rows older than its time, at most its
// limit, and two pruners remove each row once.
func testPrune(t *testing.T, e env) {
	ctx := context.Background()
	now := e.clock.Now()
	c := Connection("alice", "notion", store.StateConnected)
	for i := range 7 {
		ok(t, e.st.Calls().Insert(ctx, Call(c, now.Add(-time.Duration(i+1)*time.Hour))))
	}
	keep := Call(c, now)
	ok(t, e.st.Calls().Insert(ctx, keep))
	n, err := e.st.Calls().Prune(ctx, now.Add(-30*time.Minute), 3)
	ok(t, err)
	if n != 3 {
		t.Fatalf("a prune of 3 removed %d", n)
	}
	var mu sync.Mutex
	removed := 0
	for _, err := range race(2, func(int) error {
		for {
			n, err := e.st.Calls().Prune(ctx, now.Add(-30*time.Minute), 1)
			if err != nil || n == 0 {
				return err
			}
			mu.Lock()
			removed += n
			mu.Unlock()
		}
	}) {
		ok(t, err)
	}
	if removed != 4 {
		t.Fatalf("two pruners removed %d of 4", removed)
	}
	rows, _, err := e.st.Calls().List(ctx, c.ID, store.Page{})
	ok(t, err)
	if len(rows) != 1 || rows[0].ID != keep.ID {
		t.Fatalf("left %+v", rows)
	}

	for i := range 3 {
		ok(t, e.st.Idempotency().Put(ctx, store.IdempotencyKey{Subject: "alice", Key: fmt.Sprintf("k%d", i),
			Route: "POST /connections", Status: 201, Object: "con_1", CreatedAt: now.Add(-time.Duration(i) * time.Hour)}))
	}
	n, err = e.st.Idempotency().Prune(ctx, now.Add(-30*time.Minute), 0)
	ok(t, err)
	if n != 2 {
		t.Fatalf("idempotency prune removed %d", n)
	}
	_, err = e.st.Idempotency().Get(ctx, "alice", "k0")
	ok(t, err)
}

// errInjected is the failure a transaction case injects.
var errInjected = errors.New("injected")

func testTransactions(t *testing.T, e env) {
	ctx := context.Background()
	s := Sealer(t, 1)
	c := Connection("alice", "notion", store.StateConnected)
	key := store.IdempotencyKey{Subject: "alice", Key: "tx", Route: "POST /connections", Status: 201, Object: c.ID}
	write := func(fail int) error {
		return e.st.Tx(ctx, func(tx store.Tx) error {
			if err := tx.Connections().Create(ctx, c, 10); err != nil {
				return err
			}
			if fail == 1 {
				return errInjected
			}
			if _, err := tx.Credentials().Put(ctx, c.ID, Credential(t, s, c, store.Secrets{Value: "key-value-1"})); err != nil {
				return err
			}
			if fail == 2 {
				return errInjected
			}
			if err := tx.Idempotency().Put(ctx, key); err != nil {
				return err
			}
			// What a transaction wrote, it reads.
			if _, err := tx.Connections().Get(ctx, c.ID); err != nil {
				return err
			}
			if fail == 3 {
				return errInjected
			}
			return nil
		})
	}
	absent := func() {
		t.Helper()
		_, err := e.st.Connections().Get(ctx, c.ID)
		is(t, err, store.ErrNotFound)
		_, _, err = e.st.Credentials().Get(ctx, c.ID)
		is(t, err, store.ErrNotFound)
		_, err = e.st.Idempotency().Get(ctx, key.Subject, key.Key)
		is(t, err, store.ErrNotFound)
	}
	for fail := 1; fail <= 3; fail++ {
		is(t, write(fail), errInjected)
		absent()
	}
	ok(t, write(0))
	_, err := e.st.Connections().Get(ctx, c.ID)
	ok(t, err)
	_, _, err = e.st.Credentials().Get(ctx, c.ID)
	ok(t, err)
	_, err = e.st.Idempotency().Get(ctx, key.Subject, key.Key)
	ok(t, err)
	// A statement that fails fails the transaction, and what it wrote
	// before goes with it.
	again := Connection("alice", "other", store.StateConnected)
	err = e.st.Tx(ctx, func(tx store.Tx) error {
		if err := tx.Connections().Create(ctx, again, 0); err != nil {
			return err
		}
		return tx.Idempotency().Put(ctx, key)
	})
	is(t, err, store.ErrKeyTaken)
	_, err = e.st.Connections().Get(ctx, again.ID)
	is(t, err, store.ErrNotFound)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.st.Tx(canceled, func(store.Tx) error { return nil }); err == nil {
		t.Fatal("a transaction ran on a canceled context")
	}
	ok(t, e.st.Ready(ctx))
}

func testRotation(t *testing.T, e env) {
	ctx := context.Background()
	old := Sealer(t, 1)
	stray := Sealer(t, 9)
	rotated := Sealer(t, 2, 1)
	c := Connection("alice", "notion", store.StateConnected)
	lost := Connection("alice", "lost", store.StateConnected)
	pending := Connection("alice", "pending", store.StatePending)
	Create(t, e.st, c, lost, pending)
	cred := Credential(t, old, c, store.Secrets{AccessToken: "access-token-1"})
	_, err := e.st.Credentials().Put(ctx, c.ID, cred)
	ok(t, err)
	_, err = e.st.Credentials().Put(ctx, lost.ID, Credential(t, stray, lost, store.Secrets{AccessToken: "access-token-2"}))
	ok(t, err)
	flow := Flow(t, old, pending, e.clock.Now().Add(time.Hour))
	ok(t, e.st.Flows().Put(ctx, flow))
	secret, err := old.Seal([]byte("client-secret-1"), store.RegistrationBinding("https://auth.example.com", "cb"))
	ok(t, err)
	_, err = e.st.Registrations().Put(ctx, store.Registration{Issuer: "https://auth.example.com", RedirectURI: "cb", ClientID: "c", Secret: secret})
	ok(t, err)
	_, err = e.st.Registrations().Put(ctx, store.Registration{Issuer: "https://public.example.com", RedirectURI: "cb", ClientID: "p"})
	ok(t, err)

	counts, err := store.Remaining(ctx, e.st, rotated)
	ok(t, err)
	want := map[string]store.KeyCount{
		store.TableCredentials:   {NotFirst: 1, NoKey: 1},
		store.TableFlows:         {NotFirst: 2},
		store.TableRegistrations: {NotFirst: 1},
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("before the rewrap %v, want %v", counts, want)
	}
	if _, err := e.st.Rotation().RewrapBatch(ctx, "connections", rotated.Keys(), 1, rotated.Rewrap); err == nil {
		t.Fatal("a table with no sealed values was rewrapped")
	}
	n, err := e.st.Rotation().RewrapBatch(ctx, store.TableCredentials, rotated.Keys(), 1, rotated.Rewrap)
	ok(t, err)
	if n != 1 {
		t.Fatalf("a batch rewrapped %d", n)
	}
	n, err = store.Rewrap(ctx, e.st, old, store.RewrapBatchSize)
	ok(t, err)
	if n != 0 {
		t.Fatalf("a sealer with one key rewrapped %d", n)
	}
	n, err = store.Rewrap(ctx, e.st, rotated, 1)
	ok(t, err)
	if n != 2 {
		t.Fatalf("the rewrap moved %d rows, want the flow and the registration", n)
	}
	counts, err = store.Remaining(ctx, e.st, rotated)
	ok(t, err)
	want = map[string]store.KeyCount{
		store.TableCredentials:   {NoKey: 1},
		store.TableFlows:         {},
		store.TableRegistrations: {},
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("after the rewrap %v, want %v", counts, want)
	}

	// Every ciphertext byte is kept, and the new key alone opens them.
	newOnly := Sealer(t, 2)
	got, _, err := e.st.Credentials().Get(ctx, c.ID)
	ok(t, err)
	if !bytes.Equal(got.Sealed.Ciphertext, cred.Sealed.Ciphertext) || !bytes.Equal(got.Sealed.KeyID, newOnly.Keys().First) {
		t.Fatal("the rewrap changed the ciphertext or left the old key")
	}
	_, err = newOnly.Open(got.Sealed, store.CredentialBinding(c.ID, c.Owner, store.KindOAuth, store.Meta{
		Issuer: "https://auth.example.com", TokenEndpoint: "https://auth.example.com/token",
	}, ""))
	ok(t, err)
	f, err := e.st.Flows().Get(ctx, pending.ID)
	ok(t, err)
	if !bytes.Equal(f.Verifier.Ciphertext, flow.Verifier.Ciphertext) || !bytes.Equal(f.Pending.Sealed.Ciphertext, flow.Pending.Sealed.Ciphertext) {
		t.Fatal("the rewrap changed a flow's ciphertext")
	}
	_, err = newOnly.Open(f.Verifier, store.VerifierBinding(flow.ID, pending.ID))
	ok(t, err)
	r, err := e.st.Registrations().Get(ctx, "https://auth.example.com", "cb")
	ok(t, err)
	_, err = newOnly.Open(r.Secret, store.RegistrationBinding("https://auth.example.com", "cb"))
	ok(t, err)
	n, err = store.Rewrap(ctx, e.st, store.Sealer(must(store.NewSealer())), 1)
	ok(t, err)
	if n != 0 {
		t.Fatal("a sealer with no key rewrapped")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
