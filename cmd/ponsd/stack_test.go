// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/internal/store/postgres/pgtest"
	"latere.ai/x/pons/test/stubs"
)

func TestMain(m *testing.M) {
	// The example catalog names its one secret by this variable, and the
	// GitHub-shaped entry of the tests its client's by the other.
	for name, value := range map[string]string{
		"TRACKER_CLIENT_SECRET": "tracker-client-secret-of-the-tests", "GITHUB_APP_CLIENT_SECRET": githubSecret,
	} {
		if err := os.Setenv(name, value); err != nil {
			panic(err)
		}
	}
	pgtest.Main(m)
}

// syncBuffer is a log sink a server and a test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// key is a sealing key in base64, every byte b.
func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

// upstream are the stubs a test's servers reach: the API, the
// authorization server, the connector, and the git host where git is
// installed. A test has one set, made on first use.
type upstream struct {
	api  *stubs.API
	auth *stubs.AuthServer
	git  *stubs.GitHost
	mcp  *stubs.Connector
}

var upstreams sync.Map // testing.TB to *upstream

// upstreamOf is the test's stubs. A client of the example's warehouse is
// any client named wh or wh-client, whatever its secret.
func upstreamOf(t testing.TB) *upstream {
	t.Helper()
	if u, ok := upstreams.Load(t); ok {
		return u.(*upstream)
	}
	u := &upstream{api: stubs.NewAPI(t), auth: stubs.NewAuthServer(t), mcp: stubs.NewConnector(t)}
	u.auth.AddClient("wh", "")
	u.auth.AddClient("wh-client", "")
	u.auth.AddClient(githubClient, githubSecret)
	if tt, ok := t.(*testing.T); ok {
		if _, err := stubs.GitPath(); err == nil {
			u.git = stubs.NewGitHost(tt)
			if err := u.git.Seed("acme/app.git"); err != nil {
				t.Fatal(err)
			}
		}
	}
	upstreams.Store(t, u)
	t.Cleanup(func() { upstreams.Delete(t) })
	return u
}

// ports are the stubs' listeners.
func (u *upstream) ports() []int {
	ports := []int{u.api.Port(), u.auth.Port(), u.mcp.Port()}
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

// The client of the GitHub-shaped entry at the stub authorization server.
const (
	githubClient = "Iv23exampleclientid"
	githubSecret = "github-app-client-secret-of-the-tests"
)

// returnURL is where a browser returns to after a sign-in, one of
// PONS_RETURN_URLS.
const returnURL = "https://app.example.com/connections/done"

// catalogFile writes the example catalog, its warehouse minting at the
// stub and its search at the stub connector, with an entry of kind http at
// the stub API and git host, "forge", which takes a key, one in GitHub's
// shape, "github", which signs people in at the stub authorization server,
// two of kind mcp at the stub connector, "notes", which takes a key and
// marks its tools, and "jotter", which signs people in at the stub
// authorization server, and the entries given beside them.
func catalogFile(t testing.TB, extra string) string {
	t.Helper()
	u := upstreamOf(t)
	example := strings.NewReplacer(
		"https://login.warehouse.example.org/oauth/token", u.auth.TokenURL(),
		"https://api.search.example.net/mcp", u.mcp.URL(),
	).Replace(string(catalog.Example))
	forge := `
  - name: forge
    title: Example Forge
    kind: http
    url: ` + u.api.URL() + `
    hosts: ["api.example.com", "git.example.com"]
    git: {url: "` + u.gitURL() + `", inject: {scheme: basic, username: x-access-token}}
    http: {pass_back: ["X-RateLimit-*"]}
    auth: {type: token}
  - name: github
    title: GitHub
    description: Clone, change and push the repositories you choose, and work with their issues and pull requests.
    kind: http
    url: ` + u.api.URL() + `
    git:
      url: "` + u.gitURL() + `"
      inject: {scheme: basic, username: x-access-token}
    hosts: ["api.example.com", "git.example.com"]
    http:
      pass: ["X-GitHub-Api-Version"]
      pass_back: ["X-RateLimit-*", "X-GitHub-Request-Id"]
    auth:
      type: oauth
      discovery: none
      authorize_url: ` + u.auth.AuthorizeURL() + `
      token_url: ` + u.auth.TokenURL() + `
      client: {id: ` + githubClient + `, secret: {env: GITHUB_APP_CLIENT_SECRET}}
      resource: false
      account: {url: "` + u.api.URL() + `/user", field: login}
    links:
      manage: https://github.com/apps/pons-example/installations/new
  - name: notes
    title: Example Notes
    kind: mcp
    url: ` + u.mcp.URL() + `
    auth: {type: token}
    tools: {read_only: ["search_*", "get_*", "count"], hidden: ["delete_notebook"]}
  - name: jotter
    title: Example Jotter
    kind: mcp
    url: ` + u.mcp.URL() + `
    auth:
      type: oauth
      discovery: none
      authorize_url: ` + u.auth.AuthorizeURL() + `
      token_url: ` + u.auth.TokenURL() + `
      client: {id: ` + githubClient + `, secret: {env: GITHUB_APP_CLIENT_SECRET}}
    tools: {read_only: ["search_*", "get_*", "count"]}
`
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(path, []byte(example+forge+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stack is one ponsd in process against the stubs.
type stack struct {
	t      testing.TB
	base   string
	iss    *stubs.Issuer
	logs   *syncBuffer
	env    map[string]string
	store  store.Store
	answer []answer // every answer this stack gave, for the canary
	mu     sync.Mutex
	stop   func()
	// sweepEvery, when set before the start, is how often the stack sweeps.
	sweepEvery time.Duration
	// grace, when set before the start, is how long open requests are
	// given at a stop.
	grace time.Duration
}

// answer is one response a test read.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (a answer) json(t testing.TB) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(a.body, &v); err != nil {
		t.Fatalf("not a JSON object: %d %s", a.status, a.body)
	}
	return v
}

func (a answer) code() string {
	var e struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
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

func (a answer) id(t testing.TB) string {
	t.Helper()
	id, _ := a.json(t)["id"].(string)
	if id == "" {
		t.Fatalf("no id: %d %s", a.status, a.body)
	}
	return id
}

// environment is a server's environment: the stub issuer, the example
// catalog with the extra entries, one sealing key, and the overrides.
func environment(t testing.TB, iss *stubs.Issuer, over map[string]string) map[string]string {
	env := map[string]string{
		"PONS_ADDR":         "127.0.0.1:0",
		"PONS_PUBLIC_URL":   "http://127.0.0.1:8080",
		"PONS_OIDC_ISSUERS": iss.URL(),
		"PONS_SEALING_KEYS": key(1),
		"PONS_CATALOG_FILE": catalogFile(t, ""),
		// A test makes more connections in a minute than a person does.
		"PONS_CREATES_PER_MINUTE": "1000",
		"PONS_RETURN_URLS":        returnURL + ",https://app.example.com/settings/",
	}
	maps.Copy(env, over)
	for k, v := range over {
		if v == "" {
			delete(env, k)
		}
	}
	return env
}

// startStack starts ponsd with the environment and waits until it listens.
func startStack(t testing.TB, iss *stubs.Issuer, over map[string]string, times ...time.Duration) *stack {
	t.Helper()
	s := &stack{t: t, iss: iss, logs: &syncBuffer{}, env: environment(t, iss, over)}
	if len(times) > 0 {
		s.sweepEvery = times[0]
	}
	if len(times) > 1 {
		s.grace = times[1]
	}
	roots := stubs.Roots()
	up := upstreamOf(t)
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, func(k string) string { return s.env[k] }, s.logs, Hooks{
			Ready: ready, Roots: roots, Store: func(st store.Store) { s.store = st }, SweepEvery: s.sweepEvery, FlowsEvery: s.sweepEvery, Grace: s.grace,
			Outside: dial.Options{Resolver: stubs.Resolver(), Roots: roots, Permit: stubs.Permit(up.ports()...)},
		})
	}()
	select {
	case addr := <-ready:
		s.base = "http://" + addr
	case err := <-done:
		cancel()
		t.Fatalf("the server did not start: %v\n%s", err, s.logs)
	case <-time.After(60 * time.Second):
		cancel()
		t.Fatalf("the server did not start in time\n%s", s.logs)
	}
	var once sync.Once
	s.stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("the server stopped with %v", err)
			}
		})
	}
	t.Cleanup(s.stop)
	return s
}

// do sends one request with a bearer the stub issuer minted for sub, or
// none for "".
func (s *stack) do(method, path, sub string, body any, headers ...string) answer {
	s.t.Helper()
	bearer := ""
	if sub != "" {
		bearer = s.iss.Token(sub, nil)
	}
	return s.doBearer(method, path, bearer, body, headers...)
}

// doBearer sends one request with the bearer given, or none for "".
func (s *stack) doBearer(method, path, bearer string, body any, headers ...string) answer {
	s.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			s.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		s.t.Fatal(err, cerr)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, body: raw}
	s.mu.Lock()
	s.answer = append(s.answer, a)
	s.mu.Unlock()
	return a
}

// connect makes a connection as sub.
func (s *stack) connect(sub, connector, name string, credential map[string]any, headers ...string) answer {
	s.t.Helper()
	body := map[string]any{"connector": connector}
	if name != "" {
		body["name"] = name
	}
	if credential != nil {
		body["credential"] = credential
	}
	return s.do(http.MethodPost, "/v1/connections", sub, body, headers...)
}

// dump is what the stack's store holds at rest, as text.
func (s *stack) dump() string {
	s.t.Helper()
	if m, ok := s.store.(*memory.Store); ok {
		return string(m.Dump())
	}
	return pgtest.Dump(s.t, s.env["PONS_DATABASE_URL"])
}

// everything is every answer, header and log line the stack gave.
func (s *stack) everything() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, a := range s.answer {
		for k, v := range a.header {
			b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
		}
		b.Write(a.body)
		b.WriteString("\n")
	}
	b.WriteString(s.logs.String())
	return b.String()
}

// database is a fresh Postgres database for a stack: its direct and pooled
// URLs as the environment names them.
func database(t testing.TB) map[string]string {
	direct, pooled := pgtest.Database(t)
	return map[string]string{"PONS_DATABASE_URL": direct, "PONS_DATABASE_POOL_URL": pooled, "PONS_PUBLIC_URL": "https://pons.example.com"}
}
