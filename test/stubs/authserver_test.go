// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

// The redirect address the stub sends a person back to, as Pons names it.
const callback = "https://pons.example.com/v1/callback"

// auth drives the stub authorization server by hand: over TLS to its
// loopback listener, following no redirect.
type auth struct {
	t     *testing.T
	a     *stubs.AuthServer
	c     http.Client
	local string
}

func newAuth(t *testing.T, opts ...stubs.AuthOption) *auth {
	t.Helper()
	a := stubs.NewAuthServer(t, opts...)
	h := &auth{t: t, a: a, c: *dial.Operator(dial.OperatorOptions{Roots: stubs.Roots()})}
	h.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.local = "https://127.0.0.1:" + strconv.Itoa(a.Port())
	return h
}

// send makes one request to an address under the stub's name, at its
// listener, and reads the whole answer.
func (h *auth) send(method, address string, body io.Reader, header ...string) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(h.t.Context(), method, strings.Replace(address, h.a.URL(), h.local, 1), body)
	if err != nil {
		h.t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Basic" {
			id, secret, _ := strings.Cut(header[i+1], ":")
			req.SetBasicAuth(id, secret)
			continue
		}
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := h.c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		h.t.Fatal(err, cerr)
	}
	return resp, raw
}

// metadata reads the metadata at one address: its status and members.
func (h *auth) metadata(path string) (int, map[string]any) {
	h.t.Helper()
	resp, raw := h.send(http.MethodGet, h.a.URL()+path, nil)
	md := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &md); err != nil {
			h.t.Fatal(err)
		}
	}
	return resp.StatusCode, md
}

// authorize asks for a code as a client with the redirect address, and
// answers the query of the redirect and the verifier of its proof key.
func (h *auth) authorize(client, redirect string, extra url.Values) (url.Values, string, int) {
	h.t.Helper()
	verifier := "verifier-" + strings.Repeat("v", 40)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirect}, "state": {"the-state"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {"https://api.example.com"}, "scope": {"read offline_access"},
	}
	for k, v := range extra {
		q[k] = v
	}
	resp, _ := h.send(http.MethodGet, h.a.AuthorizeURL()+"?"+q.Encode(), nil)
	if resp.StatusCode != http.StatusFound {
		return nil, verifier, resp.StatusCode
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	return loc.Query(), verifier, resp.StatusCode
}

// token posts a form to the token endpoint, the client by HTTP Basic when
// basic is "id:secret".
func (h *auth) token(form url.Values, basic string, header ...string) (*http.Response, map[string]any) {
	h.t.Helper()
	header = append(header, "Content-Type", "application/x-www-form-urlencoded")
	if basic != "" {
		header = append(header, "Basic", basic)
	}
	resp, raw := h.send(http.MethodPost, h.a.TokenURL(), strings.NewReader(form.Encode()), header...)
	out := map[string]any{}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			h.t.Fatal(err)
		}
		for k := range vals {
			out[k] = vals.Get(k)
		}
		return resp, out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatalf("not JSON: %d %s", resp.StatusCode, raw)
	}
	return resp, out
}

// exchange trades a code for tokens.
func (h *auth) exchange(code, verifier, basic string, form url.Values) (*http.Response, map[string]any) {
	h.t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {callback}}
	for k, v := range form {
		f[k] = v
	}
	return h.token(f, basic)
}

// A sign-in runs by each way a client identifies itself: a client the
// operator registered, by HTTP Basic; a client that registered itself; and a
// client id that is a URL. Refresh rotates, a spent refresh token is
// refused, a revocation is recorded, and a client's own grant mints a token.
func TestAuthorizationServerRunsASignIn(t *testing.T) {
	h := newAuth(t)
	h.a.AddClient("pons", "pons-secret+1")
	status, md := h.metadata("/.well-known/oauth-authorization-server")
	if status != http.StatusOK || md["issuer"] != h.a.Issuer() || md["token_endpoint"] != h.a.TokenURL() ||
		md["authorization_endpoint"] != h.a.AuthorizeURL() || md["revocation_endpoint"] != h.a.RevokeURL() ||
		md["registration_endpoint"] != h.a.RegisterURL() || md["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("metadata %d %v", status, md)
	}

	// A catalog client, by HTTP Basic, its secret form-encoded as RFC 6749
	// asks.
	q, verifier, status := h.authorize("pons", callback, nil)
	if status != http.StatusFound || q.Get("state") != "the-state" || q.Get("iss") != h.a.Issuer() || q.Get("code") == "" {
		t.Fatalf("authorize %d %v", status, q)
	}
	if resp, _ := h.exchange(q.Get("code"), "another-verifier", "pons:pons-secret%2B1", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a wrong verifier: %d", resp.StatusCode)
	}
	q, verifier, _ = h.authorize("pons", callback, nil)
	resp, tokens := h.exchange(q.Get("code"), verifier, "pons:pons-secret%2B1", nil)
	if resp.StatusCode != http.StatusOK || tokens["token_type"] != "Bearer" || tokens["expires_in"] != float64(3600) ||
		!strings.HasPrefix(tokens["access_token"].(string), "stub-") || tokens["scope"] != "read offline_access" {
		t.Fatalf("exchange %d %v", resp.StatusCode, tokens)
	}
	if resp, again := h.exchange(q.Get("code"), verifier, "pons:pons-secret+1", nil); resp.StatusCode != http.StatusBadRequest || again["error"] != "invalid_grant" {
		t.Fatalf("a code used twice: %d %v", resp.StatusCode, again)
	}
	first := tokens["refresh_token"].(string)
	resp, rotated := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, "pons:pons-secret+1")
	if resp.StatusCode != http.StatusOK || rotated["refresh_token"] == first || rotated["refresh_token"] == nil {
		t.Fatalf("refresh %d %v", resp.StatusCode, rotated)
	}
	if resp, spent := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, "pons:pons-secret+1"); resp.StatusCode != http.StatusBadRequest || spent["error"] != "invalid_grant" {
		t.Fatalf("a spent refresh token: %d %v", resp.StatusCode, spent)
	}
	if resp, wrong := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, "pons:not-the-secret"); resp.StatusCode != http.StatusUnauthorized || wrong["error"] != "invalid_client" {
		t.Fatalf("a wrong secret: %d %v", resp.StatusCode, wrong)
	}
	resp, _ = h.send(http.MethodPost, h.a.RevokeURL(), strings.NewReader(url.Values{"token": {rotated["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}}.Encode()),
		"Content-Type", "application/x-www-form-urlencoded", "Basic", "pons:pons-secret+1")
	if resp.StatusCode != http.StatusOK || !slices.Equal(h.a.Revoked(), []string{rotated["refresh_token"].(string)}) {
		t.Fatalf("revocation %d %v", resp.StatusCode, h.a.Revoked())
	}
	if resp, revoked := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotated["refresh_token"].(string)}}, "pons:pons-secret+1"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a revoked refresh token: %d %v", resp.StatusCode, revoked)
	}
	resp, minted := h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"query"}, "audience": {"https://api.example.com"}}, "pons:pons-secret+1")
	if resp.StatusCode != http.StatusOK || minted["access_token"] == nil || minted["refresh_token"] != nil || minted["scope"] != "query" {
		t.Fatalf("client_credentials %d %v", resp.StatusCode, minted)
	}
	if resp, _ := h.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"pons"}, "client_secret": {"pons-secret+1"}}, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("client_credentials without Basic: %d", resp.StatusCode)
	}
	if resp, other := h.token(url.Values{"grant_type": {"password"}}, "pons:pons-secret+1"); resp.StatusCode != http.StatusBadRequest || other["error"] != "unsupported_grant_type" {
		t.Fatalf("another grant: %d %v", resp.StatusCode, other)
	}

	// A client that registered itself, with a secret, sent in the form.
	h.a.Set(func(s *stubs.AuthSwitches) { s.IssueSecret = true })
	resp, raw := h.send(http.MethodPost, h.a.RegisterURL(), strings.NewReader(`{"client_name":"Pons","redirect_uris":["`+callback+`"]}`), "Content-Type", "application/json")
	var reg map[string]any
	if err := json.Unmarshal(raw, &reg); err != nil || resp.StatusCode != http.StatusCreated || reg["client_secret"] == nil || h.a.Registrations() != 1 {
		t.Fatalf("registration %d %s %v", resp.StatusCode, raw, err)
	}
	id, secret := reg["client_id"].(string), reg["client_secret"].(string)
	if _, _, status := h.authorize(id, "https://elsewhere.example.com/cb", nil); status != http.StatusBadRequest {
		t.Fatalf("a redirect address the client did not register: %d", status)
	}
	q, verifier, _ = h.authorize(id, callback, nil)
	if resp, tokens := h.exchange(q.Get("code"), verifier, "", url.Values{"client_id": {id}, "client_secret": {secret}}); resp.StatusCode != http.StatusOK || tokens["access_token"] == nil {
		t.Fatalf("a registered client's exchange %d %v", resp.StatusCode, tokens)
	}
	if resp, _ := h.send(http.MethodPost, h.a.RegisterURL(), strings.NewReader(`not json`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a registration that does not read: %d", resp.StatusCode)
	}

	// A client id that is a URL, taken only under the switch.
	doc := "https://pons.example.com/v1/client"
	if _, _, status := h.authorize(doc, callback, nil); status != http.StatusBadRequest {
		t.Fatalf("a URL client id without the switch: %d", status)
	}
	h.a.Set(func(s *stubs.AuthSwitches) { s.CIMD = true })
	q, verifier, _ = h.authorize(doc, callback, nil)
	if resp, tokens := h.exchange(q.Get("code"), verifier, "", url.Values{"client_id": {doc}}); resp.StatusCode != http.StatusOK || tokens["access_token"] == nil {
		t.Fatalf("a URL client id's exchange %d %v", resp.StatusCode, tokens)
	}
	if resp, unknown := h.exchange("x", verifier, "", url.Values{"client_id": {"nobody"}}); resp.StatusCode != http.StatusUnauthorized || unknown["error"] != "invalid_client" {
		t.Fatalf("an unknown client: %d %v", resp.StatusCode, unknown)
	}

	access, refresh := h.a.Issued()
	if len(access) != 5 || len(refresh) != 4 {
		t.Fatalf("issued %d access and %d refresh tokens", len(access), len(refresh))
	}
	var basic, cimd bool
	for _, r := range h.a.Requests() {
		basic = basic || (r.Path == "/token" && r.Basic && r.ClientID == "pons")
		cimd = cimd || (r.Path == "/authorize" && r.ClientID == doc && r.Query.Get("resource") == "https://api.example.com")
	}
	if !basic || !cimd {
		t.Fatalf("the requests were not recorded: basic %v, url client %v", basic, cimd)
	}
	if resp, _ := h.send(http.MethodGet, h.a.URL()+"/nothing", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown path: %d", resp.StatusCode)
	}
	if resp, _ := h.send(http.MethodPost, h.a.TokenURL(), strings.NewReader("%zz"), "Content-Type", "application/x-www-form-urlencoded"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a form that does not parse: %d", resp.StatusCode)
	}
}

// Each switch changes one answer of the stub and leaves the sign-in it
// does not touch working.
func TestEachAuthSwitchChangesOneAnswer(t *testing.T) {
	const wellKnown = "/.well-known/oauth-authorization-server"
	// signIn runs authorize and the exchange as the catalog client.
	signIn := func(h *auth) (url.Values, *http.Response, map[string]any) {
		h.a.AddClient("pons", "pons-secret")
		q, verifier, status := h.authorize("pons", callback, nil)
		if status != http.StatusFound {
			t.Fatalf("authorize %d", status)
		}
		resp, tokens := h.exchange(q.Get("code"), verifier, "pons:pons-secret", nil)
		return q, resp, tokens
	}
	cases := map[string]func(t *testing.T){
		"MetadataAt": func(t *testing.T) {
			h := newAuth(t, stubs.WithIssuerPath("/tenant1"), stubs.WithAuthName("login.example.com"))
			if !strings.HasPrefix(h.a.Issuer(), "https://login.example.com:") || !strings.HasSuffix(h.a.Issuer(), "/tenant1") {
				t.Fatalf("issuer %s", h.a.Issuer())
			}
			for at, path := range map[stubs.MetadataAt]string{
				stubs.MetadataOAuth:        wellKnown + "/tenant1",
				stubs.MetadataOIDCInserted: "/.well-known/openid-configuration/tenant1",
				stubs.MetadataOIDCAppended: "/tenant1/.well-known/openid-configuration",
			} {
				h.a.Set(func(s *stubs.AuthSwitches) { s.MetadataAt = at })
				for _, other := range []string{wellKnown + "/tenant1", "/.well-known/openid-configuration/tenant1", "/tenant1/.well-known/openid-configuration"} {
					status, md := h.metadata(other)
					if want := other == path; (status == http.StatusOK) != want || (want && md["issuer"] != h.a.URL()+"/tenant1") {
						t.Fatalf("at %d, %s answers %d %v", at, other, status, md)
					}
				}
			}
		},
		"NoS256": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.NoS256 = true })
			if _, md := h.metadata(wellKnown); slices.Contains(md["code_challenge_methods_supported"].([]any), any("S256")) {
				t.Fatalf("S256 is listed: %v", md)
			}
			q, _, _ := h.authorize("pons", callback, nil)
			if q != nil {
				t.Fatalf("an unknown client was redirected: %v", q)
			}
			h.a.AddClient("pons", "")
			if q, _, _ := h.authorize("pons", callback, url.Values{"code_challenge_method": {"plain"}}); q.Get("error") != "invalid_request" {
				t.Fatalf("a plain challenge: %v", q)
			}
		},
		"NoRegistration": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.NoRegistration = true })
			if _, md := h.metadata(wellKnown); md["registration_endpoint"] != nil {
				t.Fatalf("a registration endpoint: %v", md)
			}
			if resp, _ := h.send(http.MethodPost, h.a.RegisterURL(), strings.NewReader(`{}`)); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("register %d", resp.StatusCode)
			}
		},
		"CIMD": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.CIMD = true })
			if _, md := h.metadata(wellKnown); md["client_id_metadata_document_supported"] != true {
				t.Fatalf("metadata %v", md)
			}
		},
		"IssSupported": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.IssSupported = false })
			if _, md := h.metadata(wellKnown); md["authorization_response_iss_parameter_supported"] != false {
				t.Fatalf("metadata %v", md)
			}
			if q, resp, _ := signIn(h); q.Has("iss") || resp.StatusCode != http.StatusOK {
				t.Fatalf("iss sent though the metadata says not: %v", q)
			}
		},
		"IssMode": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.IssMode = stubs.IssOmit })
			if q, _, _ := signIn(h); q.Has("iss") {
				t.Fatalf("an omitted iss: %v", q)
			}
			h.a.Set(func(s *stubs.AuthSwitches) { s.IssMode = stubs.IssWrong })
			if q, _, _ := signIn(h); q.Get("iss") != stubs.WrongIssuer {
				t.Fatalf("a wrong iss: %v", q)
			}
		},
		"WrongIssuer": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.WrongIssuer = true })
			if _, md := h.metadata(wellKnown); md["issuer"] != stubs.WrongIssuer {
				t.Fatalf("metadata %v", md)
			}
		},
		"InsideEndpoint": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.InsideEndpoint = true })
			if _, md := h.metadata(wellKnown); md["token_endpoint"] != h.local+"/token" {
				t.Fatalf("metadata %v", md)
			}
		},
		"Scopes": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.Scopes = []string{"repo"} })
			if _, md := h.metadata(wellKnown); !slices.Equal(md["scopes_supported"].([]any), []any{"repo"}) {
				t.Fatalf("metadata %v", md)
			}
		},
		"Decline": func(t *testing.T) {
			h := newAuth(t)
			h.a.AddClient("pons", "")
			h.a.Set(func(s *stubs.AuthSwitches) { s.Decline = true })
			if q, _, _ := h.authorize("pons", callback, nil); q.Get("error") != "access_denied" || q.Has("code") || q.Get("state") != "the-state" {
				t.Fatalf("a decline: %v", q)
			}
		},
		"RefuseCode": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.RefuseCode = true })
			if _, resp, tokens := signIn(h); resp.StatusCode != http.StatusBadRequest || tokens["error"] != "invalid_grant" {
				t.Fatalf("a refused code: %d %v", resp.StatusCode, tokens)
			}
		},
		"RefuseRefresh": func(t *testing.T) {
			h := newAuth(t)
			_, _, tokens := signIn(h)
			h.a.Set(func(s *stubs.AuthSwitches) { s.RefuseRefresh = true })
			if resp, out := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}, "pons:pons-secret"); resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_grant" {
				t.Fatalf("a refused refresh: %d %v", resp.StatusCode, out)
			}
		},
		"RefuseClient": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.RefuseClient = true })
			if _, resp, tokens := signIn(h); resp.StatusCode != http.StatusUnauthorized || tokens["error"] != "invalid_client" {
				t.Fatalf("a refused client: %d %v", resp.StatusCode, tokens)
			}
		},
		"NoRefreshToken": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.NoRefreshToken = true })
			if _, resp, tokens := signIn(h); resp.StatusCode != http.StatusOK || tokens["refresh_token"] != nil {
				t.Fatalf("no refresh token: %v", tokens)
			}
		},
		"TokenType": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.TokenType = "mac" })
			if _, _, tokens := signIn(h); tokens["token_type"] != "mac" {
				t.Fatalf("token type %v", tokens)
			}
		},
		"ExpiresIn": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.ExpiresIn = 0 })
			if _, _, tokens := signIn(h); tokens["expires_in"] != nil {
				t.Fatalf("a lifetime: %v", tokens)
			}
		},
		"SlowToken": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.SlowToken = 200 * time.Millisecond })
			start := time.Now()
			if _, resp, _ := signIn(h); resp.StatusCode != http.StatusOK || time.Since(start) < 200*time.Millisecond {
				t.Fatalf("a slow answer came at %v", time.Since(start))
			}
		},
		"FailRevoke": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.FailRevoke = true })
			if resp, _ := h.send(http.MethodPost, h.a.RevokeURL(), strings.NewReader("token=x"), "Content-Type", "application/x-www-form-urlencoded"); resp.StatusCode != http.StatusInternalServerError || len(h.a.Revoked()) != 0 {
				t.Fatalf("revoke %d", resp.StatusCode)
			}
		},
		"IssueSecret": func(t *testing.T) {
			h := newAuth(t)
			_, raw := h.send(http.MethodPost, h.a.RegisterURL(), strings.NewReader(`{"redirect_uris":["`+callback+`"]}`), "Content-Type", "application/json")
			if strings.Contains(string(raw), "client_secret") {
				t.Fatalf("a secret without the switch: %s", raw)
			}
		},
		"TokenPrefix": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.TokenPrefix = "canary-" })
			_, _, tokens := signIn(h)
			if !strings.HasPrefix(tokens["access_token"].(string), "canary-") || !strings.HasPrefix(tokens["refresh_token"].(string), "canary-") {
				t.Fatalf("tokens %v", tokens)
			}
		},
		"GitHub": func(t *testing.T) {
			h := newAuth(t)
			h.a.Set(func(s *stubs.AuthSwitches) { s.GitHub = true })
			_, resp, tokens := signIn(h)
			if ct := resp.Header.Get("Content-Type"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
				tokens["refresh_token_expires_in"] != "15897600" || tokens["access_token"] == "" {
				t.Fatalf("form encoding unless asked: %d %s %v", resp.StatusCode, ct, tokens)
			}
			refresh := tokens["refresh_token"].(string)
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
			resp, rotated := h.token(form, "pons:pons-secret", "Accept", "application/json")
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || rotated["refresh_token_expires_in"] != float64(15897600) {
				t.Fatalf("JSON when asked: %v", rotated)
			}
			if resp, spent := h.token(form, "pons:pons-secret", "Accept", "application/json"); resp.StatusCode != http.StatusOK || spent["error"] != "bad_refresh_token" {
				t.Fatalf("a spent refresh token: %d %v", resp.StatusCode, spent)
			}
			q, _, _ := h.authorize("pons", callback, nil)
			if resp, bad := h.exchange(q.Get("code"), "not-the-verifier", "pons:pons-secret", nil); resp.StatusCode != http.StatusOK || bad["error"] != "bad_verification_code" {
				t.Fatalf("a bad code: %d %v", resp.StatusCode, bad)
			}
			if resp, bad := h.token(form, "pons:wrong"); resp.StatusCode != http.StatusOK || bad["error"] != "incorrect_client_credentials" {
				t.Fatalf("a wrong secret: %d %v", resp.StatusCode, bad)
			}
		},
	}
	for name, run := range cases {
		t.Run(name, run)
	}
}
