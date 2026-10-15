// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// callback sends the callback a query and reads where it sent the browser.
func (r *rig) callback(q url.Values) url.Values {
	r.t.Helper()
	dest, err := r.s.Callback(context.Background(), q)
	if err != nil {
		r.t.Fatal(err)
	}
	u, perr := url.Parse(dest)
	if perr != nil || !strings.HasPrefix(dest, "https://app.example.com/back?") {
		r.t.Fatalf("the browser was sent to %q", dest)
	}
	return u.Query()
}

// The authorization request carries the S256 challenge, state, resource
// and the selected scopes, and the store holds only the hash of state and a
// sealed verifier.
func TestAuthorizationRequest(t *testing.T) {
	r := newRig(t)
	r.api.Protect([]string{"repo"}, r.auth.Issuer())
	c, address, f := r.pending("alice", "named", []string{"gist"})
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !strings.HasPrefix(address, r.auth.AuthorizeURL()+"?") || q.Get("response_type") != "code" || q.Get("client_id") != "pons-client" ||
		q.Get("redirect_uri") != "https://pons.example.com/v1/callback" || q.Get("code_challenge_method") != "S256" ||
		len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || q.Get("resource") != r.api.URL() || q.Get("scope") != "repo gist offline_access" {
		t.Fatalf("the request %v", q)
	}
	stored, err := r.st.Flows().Get(context.Background(), c.ID)
	if err != nil || !bytes.Equal(stored.StateHash, hash(q.Get("state"))) || stored.Verifier.Zero() || stored.ExpiresAt.Sub(r.clock.now()) != FlowTime {
		t.Fatalf("the flow %+v %v", stored, err)
	}
	dump := string(r.st.Dump())
	if strings.Contains(dump, q.Get("state")) || f.ReturnTo != "https://app.example.com/back" {
		t.Fatal("the state is at rest")
	}
	verifier, err := r.sealer.Open(stored.Verifier, store.VerifierBinding(f.ID, c.ID))
	if err != nil || challengeOf(string(verifier)) != q.Get("code_challenge") || strings.Contains(dump, string(verifier)) {
		t.Fatalf("the verifier: %v", err)
	}
	if _, _, err := r.s.Begin(c, Plan{AuthorizationEndpoint: "::"}, ""); err == nil {
		t.Fatal("an authorization endpoint that is no URL")
	}
	empty, err := store.NewSealer()
	if err != nil {
		t.Fatal(err)
	}
	r.s.Sealer = empty
	if _, _, err := r.s.Begin(c, Plan{AuthorizationEndpoint: r.auth.AuthorizeURL()}, ""); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("no sealing key: %v", err)
	}
}

// tokenCalls counts the stub's code exchanges.
func (r *rig) tokenCalls() int { return r.tokenRequests("authorization_code") }

// The four rows of the iss table hold, and a refused answer sends no code
// to any token endpoint.
func TestIssuerValidation(t *testing.T) {
	r := newRig(t)
	// The metadata says iss is sent, and it is: compared, and a match
	// passes.
	_, address, _ := r.pending("a1", "issued", nil)
	if q := r.callback(browser(t, address)); q.Get("code") == "" {
		t.Fatalf("a matching iss: %v", q)
	}
	// It is sent and differs: refused, no code sent.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssMode = stubs.IssWrong })
	_, address, _ = r.pending("a2", "issued", nil)
	before := r.tokenCalls()
	if q := r.callback(browser(t, address)); q.Get("error") != "sign_in_failed" {
		t.Fatalf("a wrong iss: %v", q)
	}
	// The metadata says it is sent and it is absent: refused.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssMode = stubs.IssOmit })
	_, address, _ = r.pending("a3", "issued", nil)
	if q := r.callback(browser(t, address)); q.Get("error") != "sign_in_failed" {
		t.Fatalf("an absent iss the metadata promised: %v", q)
	}
	if r.tokenCalls() != before {
		t.Fatal("a refused answer's code reached a token endpoint")
	}
	// The metadata does not say it, and it is absent: accepted from a
	// server the catalog names, by its issuer or by its endpoints.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssMode = stubs.IssAsSaid; sw.IssSupported = false })
	_, address, _ = r.pending("a4", "issued", nil)
	if q := r.callback(browser(t, address)); q.Get("code") == "" {
		t.Fatalf("an absent iss from a named server: %v", q)
	}
	_, address, _ = r.pending("a5", "code", nil)
	if q := r.callback(browser(t, address)); q.Get("code") == "" {
		t.Fatalf("an absent iss from endpoints the catalog gives: %v", q)
	}
	// It does not say it, and it is present: compared.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssMode = stubs.IssWrong })
	_, address, _ = r.pending("a6", "issued", nil)
	if q := r.callback(browser(t, address)); q.Get("error") != "sign_in_failed" {
		t.Fatalf("a wrong iss the metadata did not promise: %v", q)
	}
	// An entry with no issuer refuses any iss.
	_, address, _ = r.pending("a7", "code", nil)
	if q := r.callback(browser(t, address)); q.Get("error") != "sign_in_failed" {
		t.Fatalf("an iss where no issuer is recorded: %v", q)
	}
	// The comparison is of strings.
	f := store.Flow{Issuer: "https://auth.example.com"}
	for _, iss := range []string{"https://AUTH.example.com", "https://auth.example.com/", "https://auth.example.com:443"} {
		if issAccepted(url.Values{"iss": {iss}}, f, r.conns["issued"], false) {
			t.Errorf("%s matched by normalization", iss)
		}
	}
	if issAccepted(url.Values{"iss": {f.Issuer, f.Issuer}}, f, r.conns["issued"], false) {
		t.Error("a repeated iss")
	}
}

// A hostile server a person's connector named, which sends the person on to
// an honest one whose answer carries no iss, receives no code: the answer
// is refused at the callback.
func TestAMixUpWithoutIssIsRefused(t *testing.T) {
	r := newRig(t)
	// The connector finds its server through its metadata and the catalog
	// names none, so an answer without iss is not trusted.
	r.api.Protect([]string{"repo"}, r.auth.Issuer())
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true; sw.IssSupported = false })
	_, address, f := r.pending("alice", "found", nil)
	if f.IssParameterSupported {
		t.Fatal("the flow recorded an iss the metadata did not promise")
	}
	before := r.tokenCalls()
	q := browser(t, address)
	if q.Has("iss") {
		t.Fatal("the stub sent iss")
	}
	if got := r.callback(q); got.Get("error") != "sign_in_failed" {
		t.Fatalf("an answer without iss from a server the catalog does not name: %v", got)
	}
	if r.tokenCalls() != before {
		t.Fatal("the code reached a token endpoint")
	}
}

// An unknown state is ErrNoFlow; a second callback finds no flow; a late
// one is flow_expired; an error answer ends the flow with the service's
// word or sign_in_failed.
func TestCallbackIsOnce(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	for _, q := range []url.Values{{}, {"state": {"no-flow-has-this"}, "code": {"c"}}} {
		if _, err := r.s.Callback(ctx, q); !errors.Is(err, ErrNoFlow) {
			t.Fatalf("%v: %v", q, err)
		}
	}
	_, address, _ := r.pending("alice", "issued", nil)
	q := browser(t, address)
	if got := r.callback(q); got.Get("code") == "" || got.Get("connection") == "" {
		t.Fatalf("the first callback %v", got)
	}
	if _, err := r.s.Callback(ctx, q); !errors.Is(err, ErrNoFlow) {
		t.Fatalf("a second callback: %v", err)
	}
	_, address, _ = r.pending("bob", "issued", nil)
	q = browser(t, address)
	r.clock.add(FlowTime)
	if got := r.callback(q); got.Get("error") != "flow_expired" {
		t.Fatalf("a late callback: %v", got)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.Decline = true })
	_, address, _ = r.pending("carol", "issued", nil)
	if got := r.callback(browser(t, address)); got.Get("error") != "access_denied" {
		t.Fatalf("a person who declines: %v", got)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.Decline = false; sw.RefuseCode = true })
	_, address, _ = r.pending("dave", "issued", nil)
	if got := r.callback(browser(t, address)); got.Get("error") != "sign_in_failed" {
		t.Fatalf("a refused code: %v", got)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseCode = false })
	_, _, f := r.pending("erin", "issued", nil)
	for _, q := range []url.Values{
		{"error": {"server_error"}, "iss": {r.auth.Issuer()}},
		{"iss": {r.auth.Issuer()}},
	} {
		state := secret()
		f.StateHash, f.ExpiresAt = hash(state), r.clock.now().Add(time.Minute)
		if err := r.st.Flows().Put(ctx, f); err != nil {
			t.Fatal(err)
		}
		q.Set("state", state)
		if got := r.callback(q); got.Get("error") != "sign_in_failed" {
			t.Fatalf("%v: %v", q, got)
		}
	}
	// A connection whose connector left the catalog.
	c, address, _ := r.pending("frank", "issued", nil)
	q = browser(t, address)
	issued := r.conns["issued"]
	delete(r.conns, "issued")
	if got := r.callback(q); got.Get("error") != "sign_in_failed" {
		t.Fatalf("a connector that left: %v", got)
	}
	r.conns["issued"] = issued
	if err := r.st.Connections().Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got := back(store.Flow{ReturnTo: "%zz"}, "error", "x"); got != "%zz" {
		t.Fatalf("a return address that does not parse: %q", got)
	}
}

// The confirm connects once with the right code in time; a wrong code
// ends the flow, a late one and no flow are 410, no callback yet is 409.
func TestTheConfirm(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	c, address, _ := r.pending("alice", "code", nil)
	if err := r.s.Confirm(ctx, c, "x"); apierr.Classify(err).Code != apierr.CodeConnectionNotConnected {
		t.Fatalf("no callback yet: %v", err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	code := r.callback(browser(t, address)).Get("code")
	if err := r.s.Confirm(ctx, c, "a-wrong-code"); apierr.Classify(err).Code != apierr.CodeInvalidCode {
		t.Fatalf("a wrong code: %v", err)
	}
	if err := r.s.Confirm(ctx, c, code); apierr.Classify(err).Code != apierr.CodeFlowExpired {
		t.Fatalf("the right code after a wrong one: %v", err)
	}
	if _, _, err := r.st.Credentials().Get(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a connection has a credential before its confirm")
	}
	d, address, _ := r.pending("bob", "code", nil)
	code = r.callback(browser(t, address)).Get("code")
	if err := r.s.Confirm(ctx, d, code); err != nil {
		t.Fatal(err)
	}
	got := r.state(d)
	if got.State != store.StateConnected || got.Account != "octo-person" {
		t.Fatalf("the confirmed connection %+v", got)
	}
	if err := r.s.Confirm(ctx, got, code); apierr.Classify(err).Code != apierr.CodeFlowExpired {
		t.Fatalf("a second confirm: %v", err)
	}
	e, address, _ := r.pending("carol", "code", nil)
	code = r.callback(browser(t, address)).Get("code")
	r.clock.add(ConfirmTime)
	if err := r.s.Confirm(ctx, e, code); apierr.Classify(err).Code != apierr.CodeFlowExpired {
		t.Fatalf("a late confirm: %v", err)
	}
}

// A sign-in against the stub in GitHub's manner, form encoding unless
// asked, errors with status 200, a rotating refresh token, connects, and
// the connection's account is the stub API's login.
func TestGitHubManner(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub, sw.IssSupported = true, false })
	r.api.SetLogin("the-github-login")
	c := r.signIn("alice", "code")
	if c.State != store.StateConnected || c.Account != "the-github-login" {
		t.Fatalf("%+v", c)
	}
	o := r.open(c)
	if o.Meta.RefreshExpiresAt.IsZero() || c.ExpiresAt.IsZero() || o.Meta.AccessExpiresAt.IsZero() {
		t.Fatalf("the lifetimes: %+v", o.Meta)
	}
	for _, q := range r.auth.Requests() {
		if q.Path == "/token" && q.Header.Get("Accept") != "application/json" {
			t.Fatalf("a token request did not ask for JSON: %v", q.Header)
		}
	}
	next, err := r.s.Refresh(ctx, o)
	if err != nil || next.Secrets.RefreshToken == o.Secrets.RefreshToken {
		t.Fatalf("a rotation: %v", err)
	}
	// An error with status 200: a spent refresh token is a grant refused.
	if _, err := r.s.refreshGrant(ctx, o); !isCode(err, errInvalidGrant) {
		t.Fatalf("a spent refresh token: %v", err)
	}
	// The stub answers form encoding to a request that does not ask for
	// JSON, which the sign-in also reads.
	m, err := members([]byte("access_token=a&token_type=bearer&expires_in=28800"))
	if err != nil || text(m["access_token"]) != "a" || number(m["expires_in"]) != 28800 {
		t.Fatalf("a form answer: %v %v", m, err)
	}
}

// An authorize_url with a query, as Google's entries give it
// (specs/015-google-connectors.md): the request carries the query's members
// as written beside the sign-in's own, every member the sign-in adds is one
// of catalog.AuthorizationMembers, and the sign-in connects.
func TestTheAuthorizeURLsQueryIsKept(t *testing.T) {
	r := newRig(t)
	// The rig's entry names no issuer, so its answers carry no iss.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	code := r.conns["code"]
	code.Auth.AuthorizeURL = r.auth.AuthorizeURL() + "?access_type=offline&prompt=consent+select_account"
	r.conns["code"] = code
	_, address, _ := r.pending("alice", "code", nil)
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("access_type") != "offline" || q.Get("prompt") != "consent select_account" {
		t.Fatalf("the query's members: %v", q)
	}
	for member, values := range q {
		if member == "access_type" || member == "prompt" {
			continue
		}
		if !slices.Contains(catalog.AuthorizationMembers, member) || len(values) != 1 {
			t.Errorf("the sign-in set %s = %v, which catalog.AuthorizationMembers does not name", member, values)
		}
	}
	if q.Get("client_id") != "pons-client" || q.Get("redirect_uri") != "https://pons.example.com/v1/callback" || len(q.Get("state")) != 43 {
		t.Fatalf("the sign-in's members: %v", q)
	}
	if c := r.signIn("bob", "code"); c.State != store.StateConnected {
		t.Fatalf("%+v", c)
	}
}

// A failed read of the account leaves the account empty and the connection
// connected.
func TestAccountReadIsBestEffort(t *testing.T) {
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	r.api.Slow(time.Second)
	code := r.conns["code"]
	code.Auth.Account.URL = r.api.URL() + "/nothing"
	r.conns["code"] = code
	r.api.Slow(0)
	c := r.signIn("alice", "code")
	if c.State != store.StateConnected || c.Account != "" {
		t.Fatalf("%+v", c)
	}
	code.Auth.Account.URL = "https://nothing.example.org/user"
	r.conns["code"] = code
	if c := r.signIn("bob", "code"); c.State != store.StateConnected || c.Account != "" {
		t.Fatalf("%+v", c)
	}
	code.Auth.Account.URL = "::"
	if got := r.s.account(context.Background(), code, "t"); got != "" {
		t.Fatalf("an account url that is no URL: %q", got)
	}
}

// A reconnect asks for the union of the scopes granted and the scopes
// named, and one whose discovery finds another issuer is 422 with
// issuer_changed.
func TestReconnectAsksForTheUnion(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.Scopes = []string{"read", "write"} })
	c := r.signIn("alice", "issued")
	if o := r.open(c); o.Meta.Issuer != r.auth.Issuer() {
		t.Fatalf("the issuer kept: %+v", o.Meta)
	}
	p, err := r.s.Reconnect(ctx, c, r.conns["issued"], []string{"admin"})
	if err != nil || strings.Join(p.Scopes, " ") != "read admin" {
		t.Fatalf("the union: %v %v", p.Scopes, err)
	}
	if p, err := r.s.Reconnect(ctx, r.connection("bob", "issued", store.StatePending, nil, store.Meta{}), r.conns["issued"], nil); err != nil || p.Issuer == "" {
		t.Fatalf("a connection with no credential: %+v %v", p, err)
	}
}

// A reconnect whose discovery finds another issuer than the one its
// credential was issued under is refused, and nothing changes.
func TestReconnectKeepsItsIssuer(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	c := r.signIn("alice", "issued")
	other := stubs.NewAuthServer(t, stubs.WithAuthName("other.example.com"))
	r.s.Dial = r.dialTo(other.Port())
	moved := r.conns["issued"]
	moved.Auth.Issuer = other.Issuer()
	_, err := r.s.Reconnect(ctx, c, moved, nil)
	if e := apierr.Classify(err); e.Code != apierr.CodeSignInUnsupported || e.Reason != "issuer_changed" {
		t.Fatalf("another issuer: %v", err)
	}
	if got := r.state(c); got.State != store.StateConnected {
		t.Fatalf("the connection moved: %+v", got)
	}
}

// The sweep ends a late flow and one ended by a wrong code or an error
// answer at its next tick, revokes its pending credential, deletes a
// pending connection that never had a credential, and returns a
// reconnecting one to the state it left.
func TestSweep(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	// A late flow of a connection that never had a credential.
	never, _, _ := r.pending("alice", "code", nil)
	// One ended by a wrong code, its pending credential revoked: its
	// account holds no other credential.
	wrong, address, _ := r.pending("bob", "code", nil)
	r.api.SetLogin("bob-alone")
	r.callback(browser(t, address))
	r.api.SetLogin("octo-person")
	if err := r.s.Confirm(ctx, wrong, "a-wrong-code"); apierr.Classify(err).Code != apierr.CodeInvalidCode {
		t.Fatal(err)
	}
	// A reconnect that never came back, of a connected connection, and of
	// one with a reason.
	back := r.signIn("carol", "code")
	plan, err := r.s.Reconnect(ctx, back, r.conns["code"], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, f, err := r.s.Begin(back, plan, "https://app.example.com/back")
	if err != nil || r.st.Flows().Put(ctx, f) != nil || r.st.Connections().Move(ctx, back.ID, store.StateConnected, store.StatePending, "") != nil {
		t.Fatal(err)
	}
	refused := r.signIn("dave", "code")
	_, f, _ = r.s.Begin(refused, plan, "https://app.example.com/back")
	if r.st.Flows().Put(ctx, f) != nil || r.st.Connections().Move(ctx, refused.ID, store.StateConnected, store.StatePending, "") != nil ||
		r.st.Connections().Move(ctx, refused.ID, store.StatePending, store.StatePending, store.ReasonRevoked) != nil {
		t.Fatal("setting up a refused reconnect")
	}
	revoked := len(r.auth.Revoked())
	r.clock.add(FlowTime + time.Second)
	n, err := r.s.Sweep(ctx)
	if err != nil || n != 4 {
		t.Fatalf("swept %d: %v", n, err)
	}
	if _, err := r.st.Connections().Get(ctx, never.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a pending connection that never had a credential is kept")
	}
	if _, err := r.st.Connections().Get(ctx, wrong.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a connection whose code was wrong is kept")
	}
	if len(r.auth.Revoked()) != revoked+1 {
		t.Fatalf("revoked %d pending credentials", len(r.auth.Revoked())-revoked)
	}
	if got := r.state(back); got.State != store.StateConnected {
		t.Fatalf("a reconnect that never came back: %+v", got)
	}
	if got := r.state(refused); got.State != store.StateNeedsReconnect || got.Reason != store.ReasonRevoked {
		t.Fatalf("a reconnect with a reason: %+v", got)
	}
	if n, err := r.s.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("a second sweep took %d: %v", n, err)
	}
}

// A delete revokes at the endpoint recorded with the credential, best
// effort, and a credential nothing can open is removed without revoking.
func TestDisconnectRevokes(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	c := r.signIn("alice", "code")
	refresh := r.open(c).Secrets.RefreshToken
	if err := r.s.Disconnect(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got := r.auth.Revoked(); len(got) != 1 || got[0] != refresh {
		t.Fatalf("revoked %v", got)
	}
	var hint string
	for _, q := range r.auth.Requests() {
		if q.Path == "/revoke" {
			hint = q.Form.Get("token_type_hint")
		}
	}
	if hint != "refresh_token" {
		t.Fatalf("the hint %q", hint)
	}
	d := r.signIn("bob", "code")
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.FailRevoke = true })
	if err := r.s.Disconnect(ctx, d); err != nil {
		t.Fatalf("a failed revocation failed the delete: %v", err)
	}
	if !strings.Contains(r.logs.String(), "a revocation failed") {
		t.Fatal("a failed revocation is not logged")
	}
	e := r.signIn("carol", "code")
	other, err := store.NewSealer([32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	r.s.Sealer = other
	revoked := len(r.auth.Revoked())
	if err := r.s.Disconnect(ctx, e); err != nil {
		t.Fatal(err)
	}
	if len(r.auth.Revoked()) != revoked {
		t.Fatal("a credential nothing opens was revoked")
	}
	if _, err := r.st.Connections().Get(ctx, e.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a credential nothing opens kept its connection")
	}
	r.s.revoke(ctx, r.conns["code"], store.Meta{}, store.Secrets{})
}

// A return address is one of PONS_RETURN_URLS, or under one that ends in a
// slash, with no user part, no fragment and no dot segment.
func TestReturnAllowed(t *testing.T) {
	entries := []string{"https://app.example.com/back", "https://app.example.com/settings/"}
	for raw, ok := range map[string]bool{
		"https://app.example.com/back":                  true,
		"https://app.example.com/settings/connectors":   true,
		"https://app.example.com/settings/":             true,
		"https://app.example.com/back/more":             false,
		"https://app.example.com/backdoor":              false,
		"https://app.example.com/other":                 false,
		"https://app.example.com/settings/../admin":     false,
		"https://app.example.com/settings/%2e%2e/admin": false,
		"https://app.example.com/settings/./x":          false,
		"https://u@app.example.com/back":                false,
		"https://app.example.com/back#x":                false,
		"/back":                                         false,
		"%zz":                                           false,
	} {
		if ReturnAllowed(raw, entries) != ok {
			t.Errorf("%s", raw)
		}
	}
}
