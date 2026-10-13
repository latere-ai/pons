// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/health"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/carry"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

// upstream are the stubs a harness's server reaches: the API, the
// authorization server, and the git host where git is installed.
type upstream struct {
	api  *stubs.API
	auth *stubs.AuthServer
	git  *stubs.GitHost
}

// newUpstream starts the stubs. A client of the example's warehouse is any
// client named "wh", whatever its secret.
func newUpstream(t testing.TB) *upstream {
	t.Helper()
	u := &upstream{api: stubs.NewAPI(t), auth: stubs.NewAuthServer(t)}
	u.auth.AddClient("wh", "")
	if tt, ok := t.(*testing.T); ok {
		if _, err := stubs.GitPath(); err == nil {
			u.git = stubs.NewGitHost(tt)
			if err := u.git.Seed("acme/app.git"); err != nil {
				t.Fatal(err)
			}
		}
	}
	return u
}

// ports are the stubs' listeners, which the harness's dialer may reach.
func (u *upstream) ports() []int {
	ports := []int{u.api.Port(), u.auth.Port()}
	if u.git != nil {
		ports = append(ports, u.git.Port())
	}
	return ports
}

// gitURL is the git host's address, or the API's where git is not
// installed.
func (u *upstream) gitURL() string {
	if u.git != nil {
		return u.git.URL()
	}
	return u.api.URL()
}

// testCatalog is the example file, its warehouse minting at the stub, with
// one more entry of kind http at the stub API and one that links to where
// a person changes what the service grants.
func testCatalog(t testing.TB, u *upstream) catalog.Catalog {
	t.Helper()
	example := strings.Replace(string(catalog.Example), "https://login.warehouse.example.org/oauth/token", u.auth.TokenURL(), 1)
	extra := `
  - name: api
    title: Example API
    kind: http
    url: ` + u.api.URL() + `
    hosts: ["api.example.com", "git.example.com"]
    git: {url: "` + u.gitURL() + `"}
    auth: {type: token}
  - name: code
    title: Example Code
    kind: mcp
    url: https://mcp.code.example.com/mcp
    hosts: ["mcp.code.example.com", "api.code.example.com"]
    auth:
      type: oauth
      discovery: none
      authorize_url: https://code.example.com/authorize
      token_url: https://code.example.com/token
      client: {id: Iv23example, secret: {env: CODE_CLIENT_SECRET}}
      account: {url: "https://api.code.example.com/user", field: login}
    links: {manage: "https://code.example.com/apps/pons/installations/new"}
`
	c, err := catalog.Parse([]byte(example+extra), catalog.Options{LookupEnv: func(string) (string, bool) {
		return "client-secret-of-the-catalog", true
	}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tokens is an authenticator over plain words: the bearer is the sub, and
// the issuer is fixed. The verifier itself is access's to test.
type tokens struct{}

const issuer = "https://issuer.example.com"

func subject(sub string) string { return authz.Subject(issuer, sub) }

func (tokens) Authenticate(r *http.Request) (access.Caller, error) {
	h := r.Header.Get("Authorization")
	switch h {
	case "":
		return access.Caller{}, access.ErrMissingToken
	case "Bearer expired":
		return access.Caller{}, &access.TokenError{Reason: "expired"}
	case "Bearer unreachable":
		return access.Caller{}, &access.TokenError{Reason: "issuer_unavailable", Retryable: true}
	case "Bearer broken":
		return access.Caller{}, io.ErrUnexpectedEOF
	}
	sub := strings.TrimPrefix(h, "Bearer ")
	return access.Caller{Subject: subject(sub), Issuer: issuer, Sub: sub, Claims: map[string]any{"sub": sub}}, nil
}

// recorder is an authorizer that records every question and answers with a
// decider.
type recorder struct {
	mu     sync.Mutex
	asked  []access.Question
	decide func(access.Caller, access.Question) (access.Decision, error)
}

func (r *recorder) Authorize(ctx context.Context, c access.Caller, q access.Question) (access.Decision, error) {
	r.mu.Lock()
	r.asked = append(r.asked, q)
	decide := r.decide
	r.mu.Unlock()
	if decide != nil {
		return decide(c, q)
	}
	return access.NewAuthorizer(access.OwnerPolicy{}).Authorize(ctx, c, q)
}

func (r *recorder) questions() []access.Question {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]access.Question(nil), r.asked...)
}

func (r *recorder) set(decide func(access.Caller, access.Question) (access.Decision, error)) {
	r.mu.Lock()
	r.decide = decide
	r.mu.Unlock()
}

// harness is one API over a store.
type harness struct {
	t     testing.TB
	srv   *Server
	http  *httptest.Server
	store store.Store
	up    *upstream
	// web is the fixture's connection of kind http.
	web    string
	authz  *recorder
	logs   *bytes.Buffer
	logsMu *sync.Mutex
}

type option func(*Server)

func newHarness(t testing.TB, opts ...option) *harness {
	t.Helper()
	return newHarnessOn(t, memory.New(memory.Options{}), opts...)
}

func newHarnessOn(t testing.TB, st store.Store, opts ...option) *harness {
	t.Helper()
	sealer, err := store.NewSealer([32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: st, up: newUpstream(t), authz: &recorder{}, logs: &bytes.Buffer{}, logsMu: &sync.Mutex{}}
	h.srv = &Server{
		Store: st, Sealer: sealer, Catalog: testCatalog(t, h.up), Auth: tokens{}, Authz: h.authz,
		PublicURL: "https://pons.example.com", BasePath: "/v1",
		MaxConnectionsPerOwner: 100, CreatesPerMinute: 1000,
		Ready: []health.Check{{Name: "sealing", Run: func(context.Context) error { return nil }}},
		Log:   slog.New(slog.NewJSONHandler(lockedWriter{h.logs, h.logsMu}, nil)),
	}
	outside := dial.New(dial.Options{Resolver: stubs.Resolver(), Roots: stubs.Roots(), Permit: stubs.Permit(h.up.ports()...)})
	h.srv.Signin = &signin.Signin{Store: st, Sealer: sealer, Dial: outside, Resolve: h.srv.Resolve,
		PublicURL: h.srv.PublicURL, BasePath: h.srv.BasePath, Log: h.srv.Log}
	h.srv.Carrier = &carry.Carrier{
		Store: st, Sealer: sealer, Auth: tokens{}, Authz: h.authz, Dial: outside, Signin: h.srv.Signin, Resolve: h.srv.Resolve,
		PublicURL: h.srv.PublicURL, BasePath: h.srv.BasePath, MaxForwardBytes: 1 << 20,
		HeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxInflight: 64, MaxInflightPerSubject: 32, Log: h.srv.Log,
	}
	for _, o := range opts {
		o(h.srv)
	}
	h.http = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.http.Close)
	return h
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func (h *harness) logText() string {
	h.logsMu.Lock()
	defer h.logsMu.Unlock()
	return h.logs.String()
}

// answer is one response.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (a answer) json(t testing.TB) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(a.body, &v); err != nil {
		t.Fatalf("the body is not a JSON object: %s", a.body)
	}
	return v
}

// code is the error code of an error answer.
func (a answer) code() string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(a.body, &e); err != nil {
		return ""
	}
	return e.Error.Code
}

func (a answer) detail(name string) any {
	var e struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(a.body, &e); err != nil {
		return nil
	}
	return e.Error.Details[name]
}

// do sends one request as the bearer: a sub, or "" for none.
func (h *harness) do(method, path, bearer string, body any, headers ...string) answer {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.http.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.http.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		h.t.Fatal(err, cerr)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

// connect makes a connection of a token connector as alice.
func (h *harness) connect(bearer, connector, name, key string) answer {
	h.t.Helper()
	body := map[string]any{"connector": connector}
	if name != "" {
		body["name"] = name
	}
	if key != "" {
		body["credential"] = map[string]any{"value": key}
	}
	return h.do(http.MethodPost, h.srv.BasePath+"/connections", bearer, body)
}

func idOf(t testing.TB, a answer) string {
	t.Helper()
	id, _ := a.json(t)["id"].(string)
	if id == "" {
		t.Fatalf("no id in %d %s", a.status, a.body)
	}
	return id
}
