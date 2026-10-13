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

	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// A refresh writes the new tokens in one write: the rotated refresh token
// replaces the spent one, the version moves by one and the lease is gone;
// an answer with no refresh token keeps the old one.
func TestRotationIsOneWrite(t *testing.T) {
	r := newRig(t)
	o := r.signedIn("alice", store.StateConnected, r.clock.now().Add(30*time.Second))
	if !r.s.Due(o) {
		t.Fatal("a token ending within a minute is not due")
	}
	next, err := r.s.Fresh(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version != o.Version+1 || next.Secrets.RefreshToken == o.Secrets.RefreshToken || next.Secrets.AccessToken == o.Secrets.AccessToken {
		t.Fatalf("the refreshed credential %+v", next)
	}
	stored := r.open(o.Connection)
	if stored.Version != next.Version || stored.Secrets != next.Secrets || !stored.Meta.AccessExpiresAt.After(r.clock.now()) {
		t.Fatalf("stored %+v", stored)
	}
	if claimed, _, err := r.st.Credentials().ClaimRefresh(context.Background(), o.Connection.ID, time.Minute); err != nil || !claimed {
		t.Fatalf("the lease was left: %v %v", claimed, err)
	}
	if err := r.st.Credentials().ReleaseRefresh(context.Background(), o.Connection.ID); err != nil {
		t.Fatal(err)
	}
	// The spent refresh token is refused at the stub.
	if _, err := r.s.refreshGrant(context.Background(), o); !isCode(err, errInvalidGrant) {
		t.Fatalf("a spent refresh token: %v", err)
	}
	// An answer with no refresh token keeps the one held.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.NoRefreshToken = true })
	kept, err := r.s.Refresh(context.Background(), stored)
	if err != nil || kept.Secrets.RefreshToken != stored.Secrets.RefreshToken {
		t.Fatalf("a refresh without rotation: %+v %v", kept, err)
	}
	if o2 := r.open(o.Connection); o2.Secrets.RefreshToken != stored.Secrets.RefreshToken {
		t.Fatal("the kept refresh token was not stored")
	}
	if r.s.Due(Opened{}) || r.s.Due(next) {
		t.Fatal("a credential with no expiry or far from it is due")
	}
}

// invalid_grant moves the connection to needs_reconnect with
// refresh_refused, and one pending for a reconnect keeps its state and
// takes the reason; any other failure releases the claim, changes no state
// and answers 502.
func TestRefreshFailures(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	o := r.signedIn("alice", store.StateConnected, r.clock.now().Add(time.Hour))
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = true })
	_, err := r.s.Refresh(ctx, o)
	if e := apierr.Classify(err); e.Code != apierr.CodeConnectionNotConnected || e.Reason != store.ReasonRefreshRefused || e.Extra["state"] != "needs_reconnect" {
		t.Fatalf("a refused refresh: %v", err)
	}
	if got := r.state(o.Connection); got.State != store.StateNeedsReconnect || got.Reason != store.ReasonRefreshRefused {
		t.Fatalf("the connection %+v", got)
	}
	p := r.signedIn("bob", store.StatePending, r.clock.now().Add(time.Hour))
	if _, err := r.s.Refresh(ctx, p); apierr.Classify(err).Extra["state"] != "pending" {
		t.Fatalf("a refused refresh of a reconnecting connection: %v", err)
	}
	if got := r.state(p.Connection); got.State != store.StatePending || got.Reason != store.ReasonRefreshRefused {
		t.Fatalf("the reconnecting connection %+v", got)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = false })

	// An endpoint that cannot be reached.
	c := r.signedIn("carol", store.StateConnected, r.clock.now().Add(time.Hour))
	c.Meta.TokenEndpoint = "https://nothing.example.org/token"
	_, err = r.s.Refresh(ctx, c)
	if e := apierr.Classify(err); e.Code != apierr.CodeConnectorUnavailable || e.Reason != "refresh_failed" {
		t.Fatalf("an unreachable endpoint: %v", err)
	}
	if got := r.state(c.Connection); got.State != store.StateConnected || got.Reason != "" {
		t.Fatalf("a failed refresh moved the connection: %+v", got)
	}
	if claimed, _, err := r.st.Credentials().ClaimRefresh(ctx, c.Connection.ID, time.Minute); err != nil || !claimed {
		t.Fatalf("a failed refresh kept its claim: %v %v", claimed, err)
	}
	if !strings.Contains(r.logs.String(), `"reason":"resolve_failed"`) {
		t.Fatalf("a failed refresh is not logged with its reason: %s", r.logs)
	}
	// No refresh token: the connection moves with revoked.
	d := r.connection("dave", "code", store.StateConnected, &store.Secrets{AccessToken: "an-access-token-of-dave"}, store.Meta{TokenEndpoint: r.auth.TokenURL()})
	if _, err := r.s.Refresh(ctx, r.open(d)); apierr.Classify(err).Reason != store.ReasonRevoked {
		t.Fatalf("no refresh token: %v", err)
	}
}

// Of many callers with one expiring token, one reaches the token endpoint
// and every one uses the token it got; one that does not claim waits for
// the version to move, and gives up with a retryable 502.
func TestOneWriterRefreshes(t *testing.T) {
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.SlowToken = 200 * time.Millisecond })
	r.s.poll = 10 * time.Millisecond
	o := r.signedIn("alice", store.StateConnected, r.clock.now().Add(10*time.Second))
	var wg sync.WaitGroup
	tokens := make([]string, 12)
	errs := make([]error, 12)
	for i := range tokens {
		wg.Go(func() {
			next, err := r.s.Fresh(context.Background(), o)
			tokens[i], errs[i] = next.Secrets.AccessToken, err
		})
	}
	wg.Wait()
	for i := range tokens {
		if errs[i] != nil || tokens[i] != tokens[0] || tokens[0] == o.Secrets.AccessToken {
			t.Fatalf("caller %d: %q %v", i, tokens[i], errs[i])
		}
	}
	if n := r.tokenRequests("refresh_token"); n != 1 {
		t.Fatalf("%d refreshes reached the token endpoint", n)
	}
	// A caller that opened before another's refresh uses the stored one.
	stale, err := r.s.Refresh(context.Background(), o)
	if err != nil || stale.Secrets.AccessToken != tokens[0] || r.tokenRequests("refresh_token") != 1 {
		t.Fatalf("a stale caller: %+v %v", stale, err)
	}
	// A claim held elsewhere that never completes: the waiter gives up.
	fresh := r.open(o.Connection)
	if claimed, _, err := r.st.Credentials().ClaimRefresh(context.Background(), o.Connection.ID, time.Minute); err != nil || !claimed {
		t.Fatal(err)
	}
	r.s.wait = 50 * time.Millisecond
	_, err = r.s.Refresh(context.Background(), fresh)
	if e := apierr.Classify(err); e.Code != apierr.CodeConnectorUnavailable || e.Retryable == nil || !*e.Retryable {
		t.Fatalf("a wait with no change: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.s.await(ctx, fresh); !errors.Is(err, context.Canceled) {
		t.Fatalf("a caller that went away: %v", err)
	}
}

// A client_credentials token is minted once per process until 60 seconds
// before its expiry, again after, anew when renewed, and appears in no
// table; a refused client moves the connection.
func TestMintedTokenIsNotStored(t *testing.T) {
	r := newRig(t)
	r.auth.AddClient("wh-client", "the-client-secret-01")
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.ExpiresIn = 120; sw.TokenPrefix = "minted-canary-" })
	c := r.connection("alice", "minted", store.StateConnected, &store.Secrets{ClientSecret: "the-client-secret-01"},
		store.Meta{ClientID: "wh-client", TokenEndpoint: r.auth.TokenURL(), Scopes: []string{"read"}, Audience: "https://api.example.com"})
	o := r.open(c)
	ctx := context.Background()
	first, err := r.s.Mint(ctx, o, false)
	if err != nil || !strings.HasPrefix(first, "minted-canary-") {
		t.Fatalf("%q %v", first, err)
	}
	if again, err := r.s.Mint(ctx, o, false); err != nil || again != first || r.tokenRequests("client_credentials") != 1 {
		t.Fatalf("a kept token: %q %v", again, err)
	}
	last := r.auth.Requests()[len(r.auth.Requests())-1]
	if !last.Basic || last.Form.Get("scope") != "read" || last.Form.Get("audience") != "https://api.example.com" {
		t.Fatalf("the mint %+v", last)
	}
	r.clock.add(61 * time.Second)
	if next, err := r.s.Mint(ctx, o, false); err != nil || next == first || r.tokenRequests("client_credentials") != 2 {
		t.Fatalf("a token within a minute of its end: %q %v", next, err)
	}
	if renewed, err := r.s.Mint(ctx, o, true); err != nil || r.tokenRequests("client_credentials") != 3 || renewed == "" {
		t.Fatalf("a renewed token: %v", err)
	}
	if strings.Contains(string(r.st.Dump()), "minted-canary-") {
		t.Fatal("a minted token is at rest")
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.ExpiresIn = 0 })
	if _, err := r.s.Mint(ctx, o, true); err != nil {
		t.Fatal(err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = true })
	if _, err := r.s.Mint(ctx, o, true); apierr.Classify(err).Reason != store.ReasonCredentialRefused {
		t.Fatalf("a refused client: %v", err)
	}
	if got := r.state(c); got.State != store.StateNeedsReconnect {
		t.Fatalf("a refused client did not move its connection: %+v", got)
	}
	if err := r.s.FirstMint(ctx, r.conns["minted"], o.Meta, "x-secret-0001"); apierr.Classify(err).Code != apierr.CodeCredentialRefused {
		t.Fatalf("a refused first mint: %v", err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = false })
	if err := r.s.FirstMint(ctx, r.conns["minted"], o.Meta, "the-client-secret-01"); err != nil {
		t.Fatalf("a first mint: %v", err)
	}
	gone := o.Meta
	gone.TokenEndpoint = "https://nothing.example.org/token"
	if err := r.s.FirstMint(ctx, r.conns["minted"], gone, "the-client-secret-01"); apierr.Classify(err).Code != apierr.CodeConnectorUnreachable {
		t.Fatalf("an unreachable endpoint at connect: %v", err)
	}
	o.Meta = gone
	if _, err := r.s.Mint(ctx, o, true); apierr.Classify(err).Code != apierr.CodeConnectorUnavailable {
		t.Fatalf("an unreachable endpoint at use: %v", err)
	}
}

// The token endpoint's answer is read as JSON or as a form, an error member
// is an error whatever the status, a service's own words are the
// standard's, and a token of another type is refused.
func TestTheTokenEndpointsHabits(t *testing.T) {
	for raw, want := range map[string]string{
		`{"error":"bad_refresh_token"}`:                   errInvalidGrant,
		"error=bad_verification_code&error_description=x": errInvalidGrant,
		`{"error":"incorrect_client_credentials"}`:        errInvalidClient,
		`{"error":"slow_down"}`:                           "slow_down",
	} {
		m, err := members([]byte(raw))
		if err != nil || standard(text(m["error"])) != want {
			t.Errorf("%s: %v %v", raw, m, err)
		}
	}
	if _, err := members([]byte("")); err == nil {
		t.Error("an empty answer reads")
	}
	if number("3600") != 3600 || number(3600.0) != 3600 || number("x") != 0 || number(-1.0) != 0 || number(nil) != 0 {
		t.Error("lifetimes")
	}
	if reasonOf(errors.New("x")) != "failed" || reasonOf(&tokenError{Code: "c"}) != "c" || (&tokenError{Code: "c"}).Error() == "" {
		t.Error("reasons")
	}
	if _, err := hostOf("::"); err == nil {
		t.Error("a host of no URL")
	}
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.TokenType = "mac" })
	o := r.signedIn("alice", store.StateConnected, time.Time{})
	if _, err := r.s.refreshGrant(context.Background(), o); !isCode(err, "token_type") {
		t.Fatalf("a token of another type: %v", err)
	}
	if r.s.RedirectURI() != "https://pons.example.com/v1/callback" || r.s.ClientDocumentURL("ctr_1") != "https://pons.example.com/v1/client/ctr_1" {
		t.Fatal("the addresses Pons hands out")
	}
}

// A refresh authenticates as the client the credential was issued to: the
// catalog's, with its secret read at use; a registration kept for the
// issuer, its secret opened; or a public client.
func TestARefreshIsTheClientsOwn(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	secret, err := r.sealer.Seal([]byte("the-registered-secret"), store.RegistrationBinding("https://auth.example.com", r.s.RedirectURI()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Registrations().Put(ctx, store.Registration{Issuer: "https://auth.example.com", RedirectURI: r.s.RedirectURI(), ClientID: "reg-1", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	r.auth.AddClient("reg-1", "the-registered-secret")
	r.auth.AddClient("public-1", "")
	for _, tc := range []struct {
		client string
		basic  bool
	}{{"reg-1", true}, {"public-1", false}, {"pons-client", true}} {
		access, refresh := r.auth.Grant(tc.client, "read")
		c := r.connection(tc.client[:3]+"x", "code", store.StateConnected, &store.Secrets{AccessToken: access, RefreshToken: refresh},
			store.Meta{Issuer: "https://auth.example.com", TokenEndpoint: r.auth.TokenURL(), ClientID: tc.client})
		if _, err := r.s.Refresh(ctx, r.open(c)); err != nil {
			t.Fatalf("%s: %v", tc.client, err)
		}
		last := r.auth.Requests()[len(r.auth.Requests())-1]
		if last.ClientID != tc.client || last.Basic != tc.basic {
			t.Fatalf("%s authenticated as %+v", tc.client, last)
		}
	}
	// A catalog secret that does not resolve fails the refresh.
	code := r.conns["code"]
	code.Auth.Client.Secret.Env = "NOTHING"
	if _, err := r.s.clientAt(ctx, code, "", "pons-client"); apierr.Classify(err).Reason != "client_secret_unresolved" {
		t.Fatalf("an unresolved secret: %v", err)
	}
	// A registration's secret no key opens.
	other, err := store.NewSealer([32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	r.s.Sealer = other
	if _, err := r.s.clientAt(ctx, r.conns["code"], "https://auth.example.com", "reg-1"); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("a secret no key opens: %v", err)
	}
	if _, err := r.s.seal(store.Connection{}, Connector{}, store.Secrets{}, store.Meta{}); err != nil {
		t.Fatalf("a seal under another key: %v", err)
	}
	empty, err := store.NewSealer()
	if err != nil {
		t.Fatal(err)
	}
	r.s.Sealer = empty
	if _, err := r.s.seal(store.Connection{}, Connector{}, store.Secrets{}, store.Meta{}); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("a seal with no key: %v", err)
	}
	if _, err := Open(ctx, r.st, other, store.Connection{ID: "con_none"}, Connector{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no credential: %v", err)
	}
	if (&Signin{}).log() == nil || (&Signin{}).newID("flw") == "" || (&Signin{}).now().IsZero() {
		t.Fatal("the defaults")
	}
}
