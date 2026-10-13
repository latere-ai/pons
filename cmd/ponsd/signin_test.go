// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/test/stubs"
)

// browser stands for the person: it follows the sign-in's redirects by
// hand, reaching a stub by its name on loopback and the server where the
// test started it, and stops at the first address that is neither: the
// client's return address. It answers that address, or the status of an
// answer that sent the browser nowhere.
func (s *stack) browser(t testing.TB, address string) (*url.URL, int) {
	t.Helper()
	dialer := &net.Dialer{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: stubs.Roots(), MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if host, port, err := net.SplitHostPort(addr); err == nil && strings.HasSuffix(host, "."+stubs.Domain) {
					addr = net.JoinHostPort("127.0.0.1", port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	next := address
	for range 6 {
		// Every address the server hands out starts with its public URL;
		// it listens where the test started it.
		next = strings.Replace(next, s.env["PONS_PUBLIC_URL"], s.base, 1)
		u, err := url.Parse(next)
		if err != nil {
			t.Fatal(err)
		}
		if u.Host == "app.example.com" {
			return u, http.StatusFound
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, next, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(next, s.base+"/v1/callback") {
			called.Lock()
			called.routes["GET /callback"] = true
			called.Unlock()
			for _, h := range []string{"Cache-Control", "Referrer-Policy"} {
				if resp.Header.Get(h) == "" {
					t.Errorf("the callback's answer has no %s", h)
				}
			}
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, resp.StatusCode
		}
		ref, err := u.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		next = ref.String()
	}
	t.Fatalf("the sign-in did not return from %s", address)
	return nil, 0
}

// started is the answer of a connect or a reconnect by sign-in.
type started struct {
	id, address string
}

// startSignIn connects a connector whose people sign in, as sub.
func (s *stack) startSignIn(t testing.TB, sub, connector string, extra map[string]any) started {
	t.Helper()
	body := map[string]any{"connector": connector, "return_to": returnURL}
	maps.Copy(body, extra)
	a := s.do(http.MethodPost, "/v1/connections", sub, body)
	if a.status != http.StatusCreated {
		t.Fatalf("connect %s: %d %s", connector, a.status, a.body)
	}
	v := a.json(t)
	conn := v["connection"].(map[string]any)
	if conn["state"] != "pending" {
		t.Fatalf("a sign-in's connection %v", conn)
	}
	return started{id: conn["id"].(string), address: v["authorization_url"].(string)}
}

// signIn runs a whole sign-in as sub: the connect, the browser, and the
// confirm with the code it brought back. It answers the connection.
func (s *stack) signIn(t testing.TB, sub, connector string) map[string]any {
	t.Helper()
	st := s.startSignIn(t, sub, connector, nil)
	back, _ := s.browser(t, st.address)
	if back == nil || back.Query().Get("connection") != st.id || back.Query().Get("code") == "" {
		t.Fatalf("the browser came back to %v", back)
	}
	a := s.do(http.MethodPost, "/v1/connections/"+st.id+"/confirm", sub, map[string]any{"code": back.Query().Get("code")})
	if a.status != http.StatusOK || a.json(t)["state"] != "connected" {
		t.Fatalf("confirm: %d %s", a.status, a.body)
	}
	return a.json(t)
}

// extraEntries are entries that find the stub authorization server the two
// other ways: by its issuer, and through the protected resource metadata
// of a connector, where Pons registers itself.
func extraEntries(t testing.TB) string {
	u := upstreamOf(t)
	u.auth.AddClient("pons-public", "")
	return `
  - name: issued
    title: Issued
    kind: http
    url: ` + u.api.URL() + `
    auth:
      type: oauth
      discovery: issuer
      issuer: ` + u.auth.Issuer() + `
      client: {id: pons-public}
      scopes: [read]
  - name: found
    title: Found
    kind: http
    url: ` + u.api.URL() + `
    auth: {type: oauth, discovery: resource}
`
}

// Connect, callback, confirm and a call work against the stub
// authorization server for each discovery value.
func TestSignInEndToEnd(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, map[string]string{"PONS_CATALOG_FILE": catalogFile(t, extraEntries(t))})
	up := upstreamOf(t)
	up.api.Protect([]string{"read"}, up.auth.Issuer())
	for _, connector := range []string{"github", "issued", "found"} {
		if connector == "github" {
			up.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub, sw.IssSupported = true, false })
		} else {
			up.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub, sw.IssSupported = false, true })
		}
		c := s.signIn(t, "alice", connector)
		before := len(up.api.Credentials())
		a := s.do(http.MethodGet, "/v1/connections/"+c["id"].(string)+"/http/user", "alice", nil)
		if a.status != http.StatusOK {
			t.Fatalf("%s: a call: %d %s", connector, a.status, a.body)
		}
		creds := up.api.Credentials()[before:]
		access, _ := up.auth.Issued()
		if len(creds) != 1 || creds[0] != "Bearer "+access[len(access)-1] {
			t.Fatalf("%s: the call carried %v", connector, creds)
		}
	}
	if up.auth.Registrations() != 1 {
		t.Fatalf("the connector found through its metadata registered %d times", up.auth.Registrations())
	}
}

// A create by sign-in answers pending with an address; the same
// Idempotency-Key answers the same connection with a new address whose flow
// replaced the first.
func TestCreateBySignIn(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	upstreamOf(t).auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	first := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "github", "return_to": returnURL}, "Idempotency-Key", "k1").json(t)
	again := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "github", "return_to": returnURL}, "Idempotency-Key", "k1").json(t)
	id := first["connection"].(map[string]any)["id"]
	if again["connection"].(map[string]any)["id"] != id || again["authorization_url"] == first["authorization_url"] {
		t.Fatalf("a repeat: %v %v", first, again)
	}
	if back, status := s.browser(t, first["authorization_url"].(string)); back != nil || status != http.StatusBadRequest {
		t.Fatalf("the first flow still answers: %v %d", back, status)
	}
	if back, _ := s.browser(t, again["authorization_url"].(string)); back == nil || back.Query().Get("connection") != id {
		t.Fatalf("the second flow: %v", back)
	}
	if a := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "github"}); a.status != http.StatusBadRequest || a.detail("field") != "return_to" {
		t.Fatalf("no return_to: %d %s", a.status, a.body)
	}
}

// A return_to that is not a configured URL and lies under no configured
// prefix is refused, and the callback redirects to the flow's return_to
// alone.
func TestReturnToIsHeldToItsURLs(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	upstreamOf(t).auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	for _, bad := range []string{"https://elsewhere.example.net/done", "https://app.example.com/connections/done/more", "https://app.example.com/connections"} {
		if a := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "github", "return_to": bad}); a.status != http.StatusBadRequest || a.detail("field") != "return_to" {
			t.Errorf("%s: %d %s", bad, a.status, a.body)
		}
	}
	st := s.startSignIn(t, "alice", "github", map[string]any{"return_to": "https://app.example.com/settings/connectors"})
	back, _ := s.browser(t, st.address)
	if back == nil || back.Scheme+"://"+back.Host+back.Path != "https://app.example.com/settings/connectors" {
		t.Fatalf("the callback sent the browser to %v", back)
	}
}

// A link's sender who chooses return_to, a page of an allowed origin
// outside the listed URLs and prefixes or a path with a dot segment, is
// refused at the connect, so the finish code reaches no page the sender
// chose.
func TestASenderCannotChooseWhereTheCodeGoes(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	for _, chosen := range []string{
		"https://app.example.com/profile/mallory",
		"https://app.example.com/settings/../profile/mallory",
		"https://app.example.com/settings/%2e%2e/profile/mallory",
		"https://app.example.com/connections/done#x",
	} {
		a := s.do(http.MethodPost, "/v1/connections", "mallory", map[string]any{"connector": "github", "return_to": chosen})
		if a.status != http.StatusBadRequest || a.detail("field") != "return_to" {
			t.Errorf("%s: %d %s", chosen, a.status, a.body)
		}
	}
	if items := s.do(http.MethodGet, "/v1/connections", "mallory", nil).json(t)["items"].([]any); len(items) != 0 {
		t.Fatalf("a refused connect stored %v", items)
	}
}

// A link sent to someone else connects nothing: the sender has no finish
// code, the receiver's confirm of the sender's connection is refused, and
// the flow expires with its tokens discarded.
func TestALinkSentToSomeoneElseConnectsNothing(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	sent := s.startSignIn(t, "mallory", "github", nil)
	// The receiver signs in with their own account; the code reaches the
	// receiver's browser and client alone.
	up.api.SetLogin("the-receiver")
	back, _ := s.browser(t, sent.address)
	code := back.Query().Get("code")
	if a := s.do(http.MethodPost, "/v1/connections/"+sent.id+"/confirm", "victim", map[string]any{"code": code}); a.status != http.StatusNotFound {
		t.Fatalf("the receiver's confirm: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodPost, "/v1/connections/"+sent.id+"/confirm", "mallory", map[string]any{"code": "a-guess"}); a.status != http.StatusBadRequest {
		t.Fatalf("the sender's guess: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodPost, "/v1/connections/"+sent.id+"/confirm", "mallory", map[string]any{"code": code}); a.status != http.StatusGone {
		t.Fatalf("the code after a wrong guess spent the flow: %d %s", a.status, a.body)
	}
	got := s.do(http.MethodGet, "/v1/connections/"+sent.id, "mallory", nil).json(t)
	if got["state"] != "pending" || got["account"] != nil {
		t.Fatalf("the sender's connection %v", got)
	}
	if _, _, err := s.store.Credentials().Get(t.Context(), sent.id); err == nil {
		t.Fatal("the sender's connection holds a credential")
	}
}

// No connection has a credential before its confirm: after the callback a
// connection is pending, holds no credential and answers a call 409.
func TestTokensWaitForTheConfirm(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	upstreamOf(t).auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	st := s.startSignIn(t, "alice", "github", nil)
	if back, _ := s.browser(t, st.address); back == nil {
		t.Fatal("no callback")
	}
	if _, _, err := s.store.Credentials().Get(t.Context(), st.id); err == nil {
		t.Fatal("a credential before the confirm")
	}
	a := s.do(http.MethodGet, "/v1/connections/"+st.id+"/http/user", "alice", nil)
	if a.status != http.StatusConflict || a.detail("reason") != "not_confirmed" {
		t.Fatalf("a call before the confirm: %d %s", a.status, a.body)
	}
}

// The confirm with the right code connects once; a second confirm and a
// late one are refused, and a wrong code spends the flow.
func TestConfirmIsOnceAndTimed(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	upstreamOf(t).auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	st := s.startSignIn(t, "alice", "github", nil)
	if a := s.do(http.MethodPost, "/v1/connections/"+st.id+"/confirm", "alice", map[string]any{"code": "x"}); a.status != http.StatusConflict {
		t.Fatalf("a confirm before the callback: %d %s", a.status, a.body)
	}
	back, _ := s.browser(t, st.address)
	code := back.Query().Get("code")
	if a := s.do(http.MethodPost, "/v1/connections/"+st.id+"/confirm", "alice", map[string]any{"code": code}); a.status != http.StatusOK {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodPost, "/v1/connections/"+st.id+"/confirm", "alice", map[string]any{"code": code}); a.status != http.StatusGone || a.code() != "flow_expired" {
		t.Fatalf("a second confirm: %d %s", a.status, a.body)
	}
	late := s.startSignIn(t, "bob", "github", nil)
	back, _ = s.browser(t, late.address)
	f, err := s.store.Flows().Get(t.Context(), late.id)
	if err != nil {
		t.Fatal(err)
	}
	f.ExpiresAt = f.CreatedAt
	if err := s.store.Flows().Put(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if a := s.do(http.MethodPost, "/v1/connections/"+late.id+"/confirm", "bob", map[string]any{"code": back.Query().Get("code")}); a.status != http.StatusGone {
		t.Fatalf("a late confirm: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodPost, "/v1/connections/"+late.id+"/confirm", "bob", map[string]any{}); a.status != http.StatusBadRequest {
		t.Fatalf("a confirm with no code: %d %s", a.status, a.body)
	}
}

// A connection being reconnected answers calls with its old credential
// until the new one is confirmed, and with the new one after.
func TestReconnectKeepsServing(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	id := s.signIn(t, "alice", "github")["id"].(string)
	call := func() string {
		t.Helper()
		if a := s.do(http.MethodGet, "/v1/connections/"+id+"/http/user", "alice", nil); a.status != http.StatusOK {
			t.Fatalf("a call: %d %s", a.status, a.body)
		}
		creds := up.api.Credentials()
		return creds[len(creds)-1]
	}
	old := call()
	back := s.do(http.MethodPost, "/v1/connections/"+id+"/reconnect", "alice", map[string]any{"return_to": returnURL})
	if back.status != http.StatusOK || back.json(t)["connection"].(map[string]any)["state"] != "pending" {
		t.Fatalf("a reconnect: %d %s", back.status, back.body)
	}
	if call() != old {
		t.Fatal("a reconnecting connection did not use its old credential")
	}
	dest, _ := s.browser(t, back.json(t)["authorization_url"].(string))
	if a := s.do(http.MethodPost, "/v1/connections/"+id+"/confirm", "alice", map[string]any{"code": dest.Query().Get("code")}); a.status != http.StatusOK {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	if call() == old {
		t.Fatal("the confirmed connection kept its old credential")
	}
	key := s.connect("alice", "forge", "", map[string]any{"value": "a-forge-key-of-alice"}).id(t)
	if a := s.do(http.MethodPost, "/v1/connections/"+key+"/reconnect", "alice", map[string]any{"return_to": returnURL}); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("a reconnect of a key: %d %s", a.status, a.body)
	}
}

// A delete revokes at the revocation endpoint recorded with the
// credential, and a failed revocation does not fail it.
func TestDeleteRevokesBestEffort(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_CATALOG_FILE": catalogFile(t, extraEntries(t))})
	up := upstreamOf(t)
	id := s.signIn(t, "alice", "issued")["id"].(string)
	_, refresh := up.auth.Issued()
	if a := s.do(http.MethodDelete, "/v1/connections/"+id, "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("a delete: %d %s", a.status, a.body)
	}
	if got := up.auth.Revoked(); len(got) != 1 || got[0] != refresh[len(refresh)-1] {
		t.Fatalf("revoked %v", got)
	}
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.FailRevoke = true })
	other := s.signIn(t, "alice", "issued")["id"].(string)
	if a := s.do(http.MethodDelete, "/v1/connections/"+other, "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("a delete whose revocation fails: %d %s", a.status, a.body)
	}
}

// The connection carries links.manage from its connector, and a disconnect
// of a connector with no revocation endpoint deletes the credential with no
// revocation request.
func TestLinksAndNoRevokeURL(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub, sw.IssSupported = true, false })
	c := s.signIn(t, "alice", "github")
	links, _ := c["links"].(map[string]any)
	if links["manage"] != "https://github.com/apps/pons-example/installations/new" || c["account"] != "octo-person" {
		t.Fatalf("the connection %v", c)
	}
	if a := s.do(http.MethodDelete, "/v1/connections/"+c["id"].(string), "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("%d %s", a.status, a.body)
	}
	for _, q := range up.auth.Requests() {
		if q.Path == "/revoke" {
			t.Fatal("a connector with no revocation endpoint was revoked")
		}
	}
	if _, _, err := s.store.Credentials().Get(t.Context(), c["id"].(string)); err == nil {
		t.Fatal("the credential is kept")
	}
}

// The documents that name Pons answer with no token.
func TestTheClientDocuments(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	doc := s.do(http.MethodGet, "/v1/client", "", nil)
	if doc.status != http.StatusOK || doc.json(t)["client_id"] != s.env["PONS_PUBLIC_URL"]+"/v1/client" || doc.header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("%d %s", doc.status, doc.body)
	}
	if a := s.do(http.MethodGet, "/v1/client/ctr_01jb2m7c0p5d8f2h6j9k3m4n7q", "", nil); a.status != http.StatusNotFound {
		t.Fatalf("no added connector: %d", a.status)
	}
	if a := s.do(http.MethodGet, "/v1/callback?state=nothing", "", nil); a.status != http.StatusBadRequest || !strings.Contains(string(a.body), "expired") || a.header.Get("Location") != "" {
		t.Fatalf("a callback no flow answers: %d %s", a.status, a.body)
	}
}

// A person connects the stub GitHub by signing in; a caller shaped like an
// agent's session clones, pushes a branch of its own, is refused a push to
// main, and lists issues through the API's address; once the person takes
// the App's access away at GitHub, the next request answers 409.
func TestGitHubEndToEnd(t *testing.T) {
	if _, err := stubs.GitPath(); err != nil {
		t.Skip(err.Error())
	}
	iss := stubs.NewIssuer(t)
	az, over := withAuthorizer(t, nil, stub.WithAllow("*"))
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionUse, Limits: map[string]any{"refs": []string{"refs/heads/agents/*"}}})
	s := startStack(t, iss, over)
	up := upstreamOf(t)
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.GitHub, sw.IssSupported = true, false })
	up.api.SetLogin("a-person-on-github")
	c := s.signIn(t, "alice", "github")
	if c["account"] != "a-person-on-github" || c["git_address"] == nil {
		t.Fatalf("the connection %v", c)
	}
	session := iss.Token("alice", map[string]any{"session": "ses_agent"})
	remote := strings.Replace(c["git_address"].(string), s.env["PONS_PUBLIC_URL"], s.base, 1) + "/acme/app.git"
	dir := t.TempDir()
	if out, err := git(t, dir, session, "clone", "--quiet", remote, "app"); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	work := dir + "/app"
	if out, err := git(t, work, session, "commit", "--quiet", "--allow-empty", "-m", "the agent's change"); err != nil {
		t.Fatalf("commit: %v %s", err, out)
	}
	if out, err := git(t, work, session, "push", "--quiet", "origin", "HEAD:refs/heads/agents/ses-agent"); err != nil {
		t.Fatalf("a push of its own branch: %v %s", err, out)
	}
	if stderr, err := gitStderr(t, work, session, "push", "origin", "HEAD:refs/heads/main"); err == nil || !strings.Contains(stderr, refusedMain) {
		t.Fatalf("a push to main: %v %s", err, stderr)
	}
	access, _ := up.auth.Issued()
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+access[len(access)-1]))
	for _, rq := range up.git.Requests() {
		if rq.Credential != basic {
			t.Fatalf("the git host saw %q", rq.Credential)
		}
	}
	issues := s.doToken(http.MethodGet, strings.Replace(c["address"].(string), s.env["PONS_PUBLIC_URL"], "", 1)+"/repos/acme/app/issues", session)
	if issues.status != http.StatusOK || !strings.Contains(issues.header.Get("Link"), "/connections/"+c["id"].(string)+"/http/repos/acme/app/issues?page=2") {
		t.Fatalf("the issues: %d %v %s", issues.status, issues.header, issues.body)
	}
	// The person takes the App's access away at GitHub: the token is
	// refused and so is its refresh token.
	up.api.Refuse()
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = true })
	a := s.doToken(http.MethodGet, strings.Replace(c["address"].(string), s.env["PONS_PUBLIC_URL"], "", 1)+"/user", session)
	if a.status != http.StatusConflict || a.code() != "connection_not_connected" || a.detail("state") != "needs_reconnect" {
		t.Fatalf("after the access was taken away: %d %s", a.status, a.body)
	}
	if out, err := git(t, work, session, "fetch", "origin"); err == nil || !strings.Contains(out, "409") {
		t.Fatalf("a fetch after the access was taken away: %v %s", err, out)
	}
}

// doToken sends one request with the given bearer, as an agent's session
// would.
func (s *stack) doToken(method, path, token string) answer {
	s.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, s.base+path, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		s.t.Fatal(err, cerr)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

// Of fifty callers on two replicas with an expiring token, one reaches the
// token endpoint, all forward with the new token, and the rotated refresh
// token is stored in the same write; on the memory store, of fifty callers
// on one.
func TestRefreshHasOneWriter(t *testing.T) {
	for name, over := range map[string]func(*testing.T) map[string]string{
		"memory":   func(*testing.T) map[string]string { return map[string]string{} },
		"postgres": func(t *testing.T) map[string]string { return database(t) },
	} {
		t.Run(name, func(t *testing.T) {
			iss := stubs.NewIssuer(t)
			env := over(t)
			up := upstreamOf(t)
			up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported, sw.ExpiresIn = false, 30 })
			one := startStack(t, iss, env)
			replicas := []*stack{one}
			if name == "postgres" {
				replicas = append(replicas, startStack(t, iss, env))
			}
			id := one.signIn(t, "alice", "github")["id"].(string)
			up.auth.Set(func(sw *stubs.AuthSwitches) { sw.SlowToken = 300 * time.Millisecond; sw.ExpiresIn = 3600 })
			before := len(up.api.Credentials())
			var wg sync.WaitGroup
			for i := range 50 {
				wg.Go(func() {
					// A connection has 16 places in flight on a replica; a
					// caller past them is answered 429 and comes back.
					s := replicas[i%len(replicas)]
					for range 100 {
						a := s.do(http.MethodGet, "/v1/connections/"+id+"/http/user", "alice", nil)
						if a.status == http.StatusOK {
							return
						}
						if a.status != http.StatusTooManyRequests {
							t.Errorf("caller %d: %d %s", i, a.status, a.body)
							return
						}
						time.Sleep(20 * time.Millisecond)
					}
					t.Errorf("caller %d never got a place", i)
				})
			}
			wg.Wait()
			refreshes := 0
			for _, q := range up.auth.Requests() {
				if q.Path == "/token" && q.Form.Get("grant_type") == "refresh_token" {
					refreshes++
				}
			}
			access, refresh := up.auth.Issued()
			if refreshes != 1 {
				t.Fatalf("%d refreshes reached the token endpoint", refreshes)
			}
			for _, cred := range up.api.Credentials()[before:] {
				if cred != "Bearer "+access[len(access)-1] {
					t.Fatalf("a caller forwarded %q", cred)
				}
			}
			_, version, err := one.store.Credentials().Get(t.Context(), id)
			if err != nil || version != 2 {
				t.Fatalf("the credential's version %d %v", version, err)
			}
			if strings.Contains(one.dump(), refresh[len(refresh)-1]) {
				t.Fatal("the rotated refresh token is at rest in the clear")
			}
		})
	}
}

// A call with an expiring token refreshes once and streams its answer.
func TestCallThatNeedsARefresh(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported, sw.ExpiresIn = false, 30 })
	id := s.signIn(t, "alice", "github")["id"].(string)
	a := s.do(http.MethodGet, "/v1/connections/"+id+"/http/stream?chunks=3&gap=10ms", "alice", nil)
	if a.status != http.StatusOK || strings.Count(string(a.body), "data:") != 3 || a.header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %s", a.status, a.body)
	}
	access, _ := up.auth.Issued()
	if creds := up.api.Credentials(); creds[len(creds)-1] != "Bearer "+access[len(access)-1] || len(access) < 2 {
		t.Fatalf("the stream did not carry the refreshed token: %v", creds)
	}
}
