// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// A delete and the sweep revoke only when no other credential holds the
// grant, of any owner, a flow's pending credential and a reconnecting
// connection's own included: the same issuer, client and account. Another
// account's credential holds another grant, and one whose account was not
// read names none to wait for. A skipped revocation is logged with its
// reason and without the account.
func TestARevocationWaitsForTheLastHolder(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	const account = "person-of-the-grant"
	r.api.SetLogin(account)
	revoked := func(want int) {
		t.Helper()
		if got := len(r.auth.Revoked()); got != want {
			t.Fatalf("%d revocations, want %d", got, want)
		}
	}
	disconnect := func(c store.Connection) {
		t.Helper()
		if err := r.s.Disconnect(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	sweep := func() {
		t.Helper()
		r.clock.add(FlowTime + time.Second)
		if _, err := r.s.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Two owners connect one account through one client: the first delete
	// leaves the grant to the second.
	alice, bob := r.signIn("alice", "code"), r.signIn("bob", "code")
	disconnect(alice)
	revoked(0)
	if logs := r.logs.String(); !strings.Contains(logs, `"reason":"grant_held"`) || strings.Contains(logs, account) {
		t.Fatalf("the skipped revocation's log: %s", logs)
	}

	// A sign-in past its callback holds the grant through its pending
	// credential, and the sweep that ends it revokes once it is the last.
	_, address, _ := r.pending("carol", "code", nil)
	r.callback(browser(t, address))
	disconnect(bob)
	revoked(0)
	sweep()
	revoked(1)

	// Another account's credential holds another grant.
	r.api.SetLogin("someone-else")
	dave := r.signIn("dave", "code")
	r.api.SetLogin(account)
	erin := r.signIn("erin", "code")
	disconnect(dave)
	revoked(2)

	// A reconnect whose sign-in runs out leaves its connection the
	// credential it holds, of the same grant, unrevoked.
	plan, err := r.s.Reconnect(ctx, erin, r.conns["code"], nil)
	if err != nil {
		t.Fatal(err)
	}
	address, f, err := r.s.Begin(erin, plan, "https://app.example.com/back")
	if err != nil || r.st.Flows().Put(ctx, f) != nil || r.st.Connections().Move(ctx, erin.ID, store.StateConnected, store.StatePending, "") != nil {
		t.Fatalf("setting up a reconnect: %v", err)
	}
	r.callback(browser(t, address))
	sweep()
	revoked(2)
	if got := r.state(erin); got.State != store.StateConnected {
		t.Fatalf("the reconnect that ran out: %+v", got)
	}
	disconnect(r.state(erin))
	revoked(3)

	// A connection whose account was not read is revoked as before.
	frank := r.signIn("frank", "issued")
	r.signIn("grace", "issued")
	if r.open(frank).Meta.Account != "" {
		t.Fatal("the entry reads no account")
	}
	disconnect(frank)
	revoked(4)
}

// gated is a store whose GrantHolders waits until every disconnect of a
// test reached it, so each counts after all of them removed their rows.
type gated struct {
	store.Store
	arrived *sync.WaitGroup
}

func (g gated) Credentials() store.Credentials {
	return gatedCredentials{Credentials: g.Store.Credentials(), arrived: g.arrived}
}

type gatedCredentials struct {
	store.Credentials
	arrived *sync.WaitGroup
}

func (c gatedCredentials) GrantHolders(ctx context.Context, g store.Grant) (int64, error) {
	c.arrived.Done()
	all := make(chan struct{})
	go func() { c.arrived.Wait(); close(all) }()
	select {
	case <-all:
	case <-time.After(10 * time.Second):
		return 0, errors.New("the other disconnect never counted the holders")
	}
	return c.Credentials.GrantHolders(ctx, g)
}

// Of the last two holders of a grant disconnected at once, each counting
// when both have reached the count, at least one revokes: the holders are
// counted after the removal, so neither sees the other's removed row.
func TestTheLastTwoDisconnectsAtOnce(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	a, b := r.signIn("alice", "code"), r.signIn("bob", "code")
	var arrived sync.WaitGroup
	arrived.Add(2)
	r.s.Store = gated{Store: r.st, arrived: &arrived}
	var wg sync.WaitGroup
	for _, c := range []store.Connection{a, b} {
		wg.Go(func() {
			if err := r.s.Disconnect(ctx, c); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(r.auth.Revoked()) == 0 {
		t.Fatalf("both disconnects skipped the revocation: %s", r.logs.String())
	}
	for _, c := range []store.Connection{a, b} {
		if _, err := r.st.Connections().Get(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s is kept", c.ID)
		}
	}
}

// A store that does not count a grant's holders leaves the grant
// unrevoked, says why, and the delete stands.
func TestAnUncountedGrantIsNotRevoked(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	c := r.signIn("alice", "code")
	r.s.Store = &broken{Store: r.st, failAt: "GrantHolders"}
	if err := r.s.Disconnect(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(r.auth.Revoked()) != 0 || !strings.Contains(r.logs.String(), `"reason":"grant_not_counted"`) {
		t.Fatalf("revoked %v, logged %s", r.auth.Revoked(), r.logs.String())
	}
	if _, err := r.st.Connections().Get(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the connection is kept")
	}
}
