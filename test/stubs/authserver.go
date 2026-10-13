// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IssMode is how the answer at the redirect address carries iss (RFC 9207).
type IssMode int

const (
	// IssAsSaid sends iss when the metadata says the server does.
	IssAsSaid IssMode = iota
	// IssOmit never sends iss, whatever the metadata says.
	IssOmit
	// IssWrong sends WrongIssuer as iss.
	IssWrong
)

// MetadataAt is which of the three addresses of RFC 8414 and OpenID Connect
// Discovery answers with the metadata; the other two answer 404.
type MetadataAt int

const (
	// MetadataOAuth is /.well-known/oauth-authorization-server{path}.
	MetadataOAuth MetadataAt = iota
	// MetadataOIDCInserted is /.well-known/openid-configuration{path}.
	MetadataOIDCInserted
	// MetadataOIDCAppended is {path}/.well-known/openid-configuration.
	MetadataOIDCAppended
)

// WrongIssuer is the issuer a switch names in place of the server's own.
const WrongIssuer = "https://wrong.example.com"

// AuthSwitches are the stub authorization server's switches, one for each
// failure the sign-in of specs/007-sign-in.md handles. AuthServer.Set
// changes them under the stub's lock, so a test may flip one while the stub
// serves.
type AuthSwitches struct {
	// MetadataAt picks the one address that serves the metadata.
	MetadataAt MetadataAt
	// NoS256 lists only plain in code_challenge_methods_supported.
	NoS256 bool
	// NoRegistration drops registration_endpoint, and /register answers 404.
	NoRegistration bool
	// CIMD sets client_id_metadata_document_supported, and an https URL is
	// then a client id the stub takes as a public client.
	CIMD bool
	// IssSupported is authorization_response_iss_parameter_supported; true
	// by default.
	IssSupported bool
	// IssMode is how the redirect carries iss.
	IssMode IssMode
	// WrongIssuer makes the metadata's issuer WrongIssuer, which differs from
	// the address it was fetched under.
	WrongIssuer bool
	// InsideEndpoint names the token endpoint at a loopback address.
	InsideEndpoint bool
	// Scopes is scopes_supported; read, write and offline_access by default.
	Scopes []string
	// Decline is a person who declines: the redirect carries
	// error=access_denied.
	Decline bool
	// RefuseCode answers a code exchange with invalid_grant.
	RefuseCode bool
	// RefuseRefresh answers a refresh with invalid_grant.
	RefuseRefresh bool
	// RefuseClient answers every request of the token endpoint with
	// invalid_client.
	RefuseClient bool
	// NoRefreshToken leaves refresh_token out of every answer.
	NoRefreshToken bool
	// TokenType is the answer's token_type; Bearer by default.
	TokenType string
	// ExpiresIn is the answer's expires_in in seconds; 3600 by default, and
	// 0 leaves it out.
	ExpiresIn int
	// RefreshExpiresIn is refresh_token_expires_in under GitHub; 15897600
	// by default.
	RefreshExpiresIn int
	// SlowToken delays every answer of the token endpoint.
	SlowToken time.Duration
	// FailRevoke answers a revocation with 500.
	FailRevoke bool
	// IssueSecret gives a registered client a secret.
	IssueSecret bool
	// TokenPrefix starts every token issued, so a test plants a canary
	// through it; "stub-" by default.
	TokenPrefix string
	// GitHub is GitHub's manner at the token endpoint: form encoding unless
	// the request accepts application/json, an error with status 200
	// (bad_verification_code, bad_refresh_token,
	// incorrect_client_credentials), and refresh_token_expires_in.
	GitHub bool
}

// AuthRequest is one request the stub served, recorded before it answered.
type AuthRequest struct {
	Method, Path string
	Query        url.Values
	Form         url.Values
	Header       http.Header
	// Body is the raw body of a registration.
	Body []byte
	// ClientID is the client the request named: by HTTP Basic, in the form
	// or in the query.
	ClientID string
	// Basic says the client authenticated with HTTP Basic.
	Basic bool
}

// AuthServer is the stub authorization server: metadata at the addresses
// of RFC 8414 and OpenID Connect Discovery, the authorization endpoint with
// the proof key, the token endpoint with a code, a rotating refresh token
// and a client's own grant, revocation (RFC 7009) and dynamic registration
// (RFC 7591). It fetches nothing: a client id that is a URL is recorded and
// taken as a public client. It is safe for concurrent use.
type AuthServer struct {
	name, path string

	mu            sync.Mutex
	url           string
	port          int
	sw            AuthSwitches
	clients       map[string]authClient
	codes         map[string]grant
	refresh       map[string]grant
	requests      []AuthRequest
	access        []string
	refreshes     []string
	revoked       []string
	registrations int
}

// authClient is a client the stub knows: a secret, empty for a public one,
// and the redirect addresses a registered one gave.
type authClient struct {
	secret    string
	redirects []string
}

// grant is what a code or a refresh token was issued for.
type grant struct {
	client, redirect, challenge, resource, scope string
	expires                                      time.Time
}

// AuthOption configures NewAuthServer.
type AuthOption func(*AuthServer)

// WithAuthName is the name the stub is reached under, auth.example.com by
// default; its certificate covers it.
func WithAuthName(name string) AuthOption { return func(a *AuthServer) { a.name = name } }

// WithIssuerPath gives the issuer a path, such as /tenant1.
func WithIssuerPath(path string) AuthOption { return func(a *AuthServer) { a.path = path } }

// NewAuthServer starts a stub authorization server for the test.
func NewAuthServer(t TB, opts ...AuthOption) *AuthServer {
	t.Helper()
	a := &AuthServer{
		name: "auth.example.com", clients: map[string]authClient{},
		codes: map[string]grant{}, refresh: map[string]grant{},
		sw: AuthSwitches{
			IssSupported: true, Scopes: []string{"read", "write", "offline_access"},
			TokenType: "Bearer", ExpiresIn: 3600, RefreshExpiresIn: 15897600, TokenPrefix: "stub-",
		},
	}
	for _, o := range opts {
		o(a)
	}
	srv := serveTLS(t, http.HandlerFunc(a.serve), a.name)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	a.mu.Lock()
	a.port = port
	a.url = "https://" + a.name + ":" + strconv.Itoa(a.port)
	a.mu.Unlock()
	return a
}

// URL is the stub's address under its name, with no path.
func (a *AuthServer) URL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.url
}

// Port is the port the stub listens on.
func (a *AuthServer) Port() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.port
}

// Issuer is the stub's issuer: its address and the issuer's path.
func (a *AuthServer) Issuer() string { return a.URL() + a.path }

// AuthorizeURL is the authorization endpoint.
func (a *AuthServer) AuthorizeURL() string { return a.URL() + "/authorize" }

// TokenURL is the token endpoint.
func (a *AuthServer) TokenURL() string { return a.URL() + "/token" }

// RevokeURL is the revocation endpoint.
func (a *AuthServer) RevokeURL() string { return a.URL() + "/revoke" }

// RegisterURL is the registration endpoint.
func (a *AuthServer) RegisterURL() string { return a.URL() + "/register" }

// AddClient adds a client the operator registered, as a catalog names one.
// An empty secret is a public client.
func (a *AuthServer) AddClient(id, secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients[id] = authClient{secret: secret}
}

// Set changes the switches under the stub's lock.
func (a *AuthServer) Set(change func(*AuthSwitches)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	change(&a.sw)
}

// Requests are the requests the stub served, in order.
func (a *AuthServer) Requests() []AuthRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.requests)
}

// Issued are the access and refresh tokens the stub issued, in order.
func (a *AuthServer) Issued() (access, refresh []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.access), slices.Clone(a.refreshes)
}

// Revoked are the tokens revocation was asked for, in order.
func (a *AuthServer) Revoked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.revoked)
}

// Registrations is how many clients registered.
func (a *AuthServer) Registrations() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.registrations
}

// maxAuthBody bounds a request body the stub reads.
const maxAuthBody = 1 << 20

// serve records the request and answers it by its path.
func (a *AuthServer) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAuthBody))
	if err != nil {
		http.Error(w, "the body did not read", http.StatusBadRequest)
		return
	}
	form := url.Values{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if form, err = url.ParseQuery(string(body)); err != nil {
			http.Error(w, "the body is not a form", http.StatusBadRequest)
			return
		}
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = form.Get("client_id"), form.Get("client_secret")
		if id == "" {
			id = r.URL.Query().Get("client_id")
		}
	}
	rec := AuthRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Form: form, Header: r.Header.Clone(), ClientID: id, Basic: basic}
	if r.URL.Path == "/register" {
		rec.Body = body
	}
	a.mu.Lock()
	a.requests = append(a.requests, rec)
	sw, base := a.sw, a.url
	a.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == a.metadataPath(sw.MetadataAt):
		writeJSONStatus(w, http.StatusOK, a.metadata(sw, base))
	case r.Method == http.MethodGet && r.URL.Path == "/authorize":
		a.authorize(w, r, sw)
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		a.token(w, r, sw, form, id, secret, basic)
	case r.Method == http.MethodPost && r.URL.Path == "/revoke":
		a.revoke(w, sw, form)
	case r.Method == http.MethodPost && r.URL.Path == "/register" && !sw.NoRegistration:
		a.register(w, sw, body)
	default:
		http.NotFound(w, r)
	}
}

// metadataPath is the one address that serves the metadata.
func (a *AuthServer) metadataPath(at MetadataAt) string {
	switch at {
	case MetadataOIDCInserted:
		return "/.well-known/openid-configuration" + a.path
	case MetadataOIDCAppended:
		return a.path + "/.well-known/openid-configuration"
	}
	return "/.well-known/oauth-authorization-server" + a.path
}

// metadata is the authorization server metadata, as the switches shape it.
func (a *AuthServer) metadata(sw AuthSwitches, base string) map[string]any {
	md := map[string]any{
		"issuer":                                         base + a.path,
		"authorization_endpoint":                         base + "/authorize",
		"token_endpoint":                                 base + "/token",
		"revocation_endpoint":                            base + "/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               sw.Scopes,
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"authorization_response_iss_parameter_supported": sw.IssSupported,
		"client_id_metadata_document_supported":          sw.CIMD,
	}
	if !sw.NoRegistration {
		md["registration_endpoint"] = base + "/register"
	}
	if sw.NoS256 {
		md["code_challenge_methods_supported"] = []string{"plain"}
	}
	if sw.WrongIssuer {
		md["issuer"] = WrongIssuer
	}
	if sw.InsideEndpoint {
		md["token_endpoint"] = "https://127.0.0.1:" + strconv.Itoa(a.Port()) + "/token"
	}
	return md
}

// knows reports whether a client id is one the stub takes, with its secret.
func (a *AuthServer) knows(sw AuthSwitches, id string) (authClient, bool) {
	a.mu.Lock()
	c, ok := a.clients[id]
	a.mu.Unlock()
	if !ok && sw.CIMD && strings.HasPrefix(id, "https://") {
		return authClient{}, true
	}
	return c, ok
}

// authorize is the authorization endpoint: a known client, a redirect
// address it may use, and the S256 proof key, answered with a redirect that
// carries a code bound to all of them.
func (a *AuthServer) authorize(w http.ResponseWriter, r *http.Request, sw AuthSwitches) {
	q := r.URL.Query()
	c, ok := a.knows(sw, q.Get("client_id"))
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if !ok || err != nil || !redirect.IsAbs() || (len(c.redirects) > 0 && !slices.Contains(c.redirects, q.Get("redirect_uri"))) {
		http.Error(w, "unknown client or redirect address", http.StatusBadRequest)
		return
	}
	answer := redirect.Query()
	answer.Set("state", q.Get("state"))
	switch {
	case sw.IssMode == IssWrong:
		answer.Set("iss", WrongIssuer)
	case sw.IssMode == IssAsSaid && sw.IssSupported:
		answer.Set("iss", a.Issuer())
	}
	switch {
	case q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		answer.Set("error", "invalid_request")
	case sw.Decline:
		answer.Set("error", "access_denied")
	default:
		code := rand.Text()
		a.mu.Lock()
		a.codes[code] = grant{
			client: q.Get("client_id"), redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
			resource: q.Get("resource"), scope: q.Get("scope"), expires: time.Now().Add(time.Minute),
		}
		a.mu.Unlock()
		answer.Set("code", code)
	}
	redirect.RawQuery = answer.Encode()
	w.Header().Set("Location", redirect.String())
	w.WriteHeader(http.StatusFound)
}

// token is the token endpoint.
func (a *AuthServer) token(w http.ResponseWriter, r *http.Request, sw AuthSwitches, form url.Values, id, secret string, basic bool) {
	if sw.SlowToken > 0 {
		select {
		case <-time.After(sw.SlowToken):
		case <-r.Context().Done():
			return
		}
	}
	fail := func(status int, code, github string) {
		if sw.GitHub {
			status, code = http.StatusOK, github
		}
		writeToken(w, r, sw, status, map[string]any{"error": code, "error_description": "the stub refused the request"})
	}
	c, known := a.knows(sw, id)
	if !known || sw.RefuseClient || (c.secret != "" && !sameSecret(c.secret, secret)) {
		fail(http.StatusUnauthorized, "invalid_client", "incorrect_client_credentials")
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		a.mu.Lock()
		g, ok := a.codes[form.Get("code")]
		delete(a.codes, form.Get("code"))
		a.mu.Unlock()
		if sw.RefuseCode || !ok || time.Now().After(g.expires) || g.client != id ||
			g.redirect != form.Get("redirect_uri") || challengeOf(form.Get("code_verifier")) != g.challenge {
			fail(http.StatusBadRequest, "invalid_grant", "bad_verification_code")
			return
		}
		a.issue(w, r, sw, g, true)
	case "refresh_token":
		a.mu.Lock()
		g, ok := a.refresh[form.Get("refresh_token")]
		delete(a.refresh, form.Get("refresh_token"))
		a.mu.Unlock()
		if sw.RefuseRefresh || !ok || g.client != id {
			fail(http.StatusBadRequest, "invalid_grant", "bad_refresh_token")
			return
		}
		a.issue(w, r, sw, g, true)
	case "client_credentials":
		if !basic {
			fail(http.StatusUnauthorized, "invalid_client", "incorrect_client_credentials")
			return
		}
		a.issue(w, r, sw, grant{client: id, scope: form.Get("scope"), resource: form.Get("audience")}, false)
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type", "unsupported_grant_type")
	}
}

// issue answers new tokens for a grant: an access token, and a refresh token
// that replaces the one spent, when the grant takes one.
func (a *AuthServer) issue(w http.ResponseWriter, r *http.Request, sw AuthSwitches, g grant, refreshable bool) {
	access := sw.TokenPrefix + rand.Text()
	answer := map[string]any{"access_token": access, "token_type": sw.TokenType}
	if g.scope != "" {
		answer["scope"] = g.scope
	}
	if sw.ExpiresIn > 0 {
		answer["expires_in"] = sw.ExpiresIn
	}
	a.mu.Lock()
	a.access = append(a.access, access)
	if refreshable && !sw.NoRefreshToken {
		refresh := sw.TokenPrefix + rand.Text()
		a.refresh[refresh] = g
		a.refreshes = append(a.refreshes, refresh)
		answer["refresh_token"] = refresh
		if sw.GitHub {
			answer["refresh_token_expires_in"] = sw.RefreshExpiresIn
		}
	}
	a.mu.Unlock()
	writeToken(w, r, sw, http.StatusOK, answer)
}

// revoke is the revocation endpoint of RFC 7009: it records the token.
func (a *AuthServer) revoke(w http.ResponseWriter, sw AuthSwitches, form url.Values) {
	if sw.FailRevoke {
		http.Error(w, "the stub fails a revocation", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.revoked = append(a.revoked, form.Get("token"))
	delete(a.refresh, form.Get("token"))
	a.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// register is dynamic registration (RFC 7591): a new client with the
// redirect addresses it named, and a secret when the switch issues one.
func (a *AuthServer) register(w http.ResponseWriter, sw AuthSwitches, body []byte) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid_client_metadata"})
		return
	}
	c := authClient{}
	if uris, ok := req["redirect_uris"].([]any); ok {
		for _, u := range uris {
			c.redirects = append(c.redirects, fmt.Sprint(u))
		}
	}
	id := "reg-" + rand.Text()
	answer := map[string]any{"client_id": id, "redirect_uris": c.redirects}
	if sw.IssueSecret {
		c.secret = rand.Text()
		answer["client_secret"] = c.secret
	}
	a.mu.Lock()
	a.clients[id] = c
	a.registrations++
	a.mu.Unlock()
	writeJSONStatus(w, http.StatusCreated, answer)
}

// challengeOf is the S256 challenge of a verifier.
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameSecret compares a secret as sent, and as the form encoding RFC 6749
// asks of HTTP Basic leaves it.
func sameSecret(want, got string) bool {
	if got == want {
		return true
	}
	unescaped, err := url.QueryUnescape(got)
	return err == nil && unescaped == want
}

// writeToken writes an answer of the token endpoint: JSON, or under GitHub
// form encoding unless the request accepts JSON.
func writeToken(w http.ResponseWriter, r *http.Request, sw AuthSwitches, status int, v map[string]any) {
	if !sw.GitHub || strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSONStatus(w, status, v)
		return
	}
	form := url.Values{}
	for k, val := range v {
		form.Set(k, fmt.Sprint(val))
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	w.WriteHeader(status)
	// A write to a test's own client that fails leaves nothing to answer.
	_, _ = io.WriteString(w, form.Encode())
}

// writeJSONStatus writes v as JSON with a status.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// v is built by the stub and always encodes; a write to a test's own
	// client that fails leaves nothing to answer.
	_ = json.NewEncoder(w).Encode(v)
}
