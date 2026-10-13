// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// errBroken is a store that fails.
var errBroken = errors.New("an injected failure of the store")

// broken is a store whose credentials fail at the method a test names, and
// whose connections fail every move and description while moves is set.
type broken struct {
	store.Store
	failAt string
	moves  bool
}

func (b *broken) Credentials() store.Credentials {
	return brokenCredentials{Credentials: b.Store.Credentials(), failAt: b.failAt}
}

func (b *broken) Connections() store.Connections {
	return brokenConnections{Connections: b.Store.Connections(), fail: b.moves}
}

type brokenCredentials struct {
	store.Credentials
	failAt string
}

func (c brokenCredentials) Get(ctx context.Context, id string) (store.SealedCredential, int64, error) {
	if c.failAt == "Get" {
		return store.SealedCredential{}, 0, errBroken
	}
	return c.Credentials.Get(ctx, id)
}

func (c brokenCredentials) ClaimRefresh(ctx context.Context, id string, lease time.Duration) (bool, int64, error) {
	if c.failAt == "ClaimRefresh" {
		return false, 0, errBroken
	}
	if c.failAt == "Moved" {
		claimed, v, err := c.Credentials.ClaimRefresh(ctx, id, lease)
		return claimed, v + 1, err
	}
	return c.Credentials.ClaimRefresh(ctx, id, lease)
}

func (c brokenCredentials) ReleaseRefresh(ctx context.Context, id string) error {
	if c.failAt == "ReleaseRefresh" || c.failAt == "Moved" {
		return errBroken
	}
	return c.Credentials.ReleaseRefresh(ctx, id)
}

func (c brokenCredentials) CompleteRefresh(ctx context.Context, id string, from int64, sealed store.SealedCredential) error {
	switch c.failAt {
	case "CompleteRefresh":
		return errBroken
	case "Superseded":
		return store.ErrVersionMoved
	}
	return c.Credentials.CompleteRefresh(ctx, id, from, sealed)
}

type brokenConnections struct {
	store.Connections
	fail bool
}

func (c brokenConnections) Move(ctx context.Context, id string, from, to store.State, reason string) error {
	if c.fail {
		return errBroken
	}
	return c.Connections.Move(ctx, id, from, to, reason)
}

func (c brokenConnections) Describe(ctx context.Context, id string, a store.Account) error {
	if c.fail {
		return errBroken
	}
	return c.Connections.Describe(ctx, id, a)
}

// A store that fails is a refresh that fails with nothing moved, and a
// refresh that lost to a newer credential uses the stored one.
func TestARefreshOverAFailingStore(t *testing.T) {
	r := newRig(t, "")
	ctx := context.Background()
	for _, at := range []string{"ClaimRefresh", "ReleaseRefresh", "CompleteRefresh", "Moved"} {
		o := r.signedIn("a"+at[:4], store.StateConnected, r.clock.now().Add(time.Hour))
		r.s.Store = &broken{Store: r.st, failAt: at}
		if at == "ReleaseRefresh" {
			r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = true })
		}
		if _, err := r.s.Refresh(ctx, o); apierr.Classify(err).Code != apierr.CodeInternal {
			t.Errorf("%s: %v", at, err)
		}
		r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = false })
		r.s.Store = r.st
	}
	o := r.signedIn("super", store.StateConnected, r.clock.now().Add(time.Hour))
	r.s.Store = &broken{Store: r.st, failAt: "Superseded"}
	if next, err := r.s.Refresh(ctx, o); err != nil || next.Version != o.Version {
		t.Fatalf("a refresh that lost: %+v %v", next, err)
	}
	// A claim another holds, read through a failing store.
	o = r.signedIn("waits", store.StateConnected, r.clock.now().Add(time.Hour))
	if claimed, _, err := r.st.Credentials().ClaimRefresh(ctx, o.Connection.ID, time.Minute); err != nil || !claimed {
		t.Fatal(err)
	}
	r.s.Store = &broken{Store: r.st, failAt: "Get"}
	r.s.poll = time.Millisecond
	if _, err := r.s.Refresh(ctx, o); apierr.Classify(err).Code != apierr.CodeInternal {
		t.Fatalf("a wait over a failing store: %v", err)
	}
	if _, err := r.s.reopen(ctx, o); apierr.Classify(err).Code != apierr.CodeInternal && !errors.Is(err, errBroken) {
		t.Fatalf("a reopen over a failing store: %v", err)
	}
	// A move that fails is an internal error; the expiry of a refresh token
	// that is not written is logged.
	r.s.Store = &broken{Store: r.st, moves: true}
	if err := Refused(ctx, r.s.Store, o.Connection, store.ReasonRevoked); apierr.Classify(err).Code != apierr.CodeInternal {
		t.Fatalf("a move over a failing store: %v", err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub = true })
	g := r.signedIn("github", store.StateConnected, r.clock.now().Add(time.Hour))
	if _, err := r.s.Refresh(ctx, g); err != nil {
		t.Fatalf("a refresh whose expiry is not written: %v", err)
	}
	if !strings.Contains(r.logs.String(), "the refresh token's expiry was not written") {
		t.Fatal("an expiry not written is not logged")
	}
}
