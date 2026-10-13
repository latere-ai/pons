// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

const issuer = "https://issuer.example.com"

func subject(sub string) string { return authz.Subject(issuer, sub) }

// bearers is an authenticator over plain words: the bearer is the sub. The
// bearer "agent" carries a session claim, as an agent's session does.
type bearers struct{}

func (bearers) Authenticate(r *http.Request) (access.Caller, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return access.Caller{}, access.ErrMissingToken
	}
	sub := strings.TrimPrefix(h, "Bearer ")
	if sub == "expired" {
		return access.Caller{}, &access.TokenError{Reason: "expired"}
	}
	claims := map[string]any{"sub": sub}
	if sub == "agent" {
		claims["session"] = map[string]any{"id": "ses_01", "note": "not read"}
	}
	return access.Caller{Subject: subject(sub), Issuer: issuer, Sub: sub, Claims: claims}, nil
}

// decider is an authorizer that records every question, allows an owner
// its own connections with the limits set for it, and fails as a test asks.
type decider struct {
	mu          sync.Mutex
	asked       []access.Question
	limits      authorizer.Limits
	unavailable bool
}

func (d *decider) Authorize(_ context.Context, c access.Caller, q access.Question) (access.Decision, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, q)
	if d.unavailable {
		return access.Decision{}, access.ErrUnavailable
	}
	owner, _ := q.Resource.Fields[authorizer.FieldOwner].(string)
	if owner != c.Subject && c.Sub != "agent" {
		return access.Decision{Reason: "not_owner"}, nil
	}
	return access.Decision{Allow: true, Limits: d.limits}, nil
}

func (d *decider) set(l authorizer.Limits) {
	d.mu.Lock()
	d.limits = l
	d.mu.Unlock()
}

func (d *decider) out(unavailable bool) {
	d.mu.Lock()
	d.unavailable = unavailable
	d.mu.Unlock()
}

func (d *decider) questions() []access.Question {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]access.Question(nil), d.asked...)
}

// counting is a sealer that counts what it opened.
type counting struct {
	store.Sealer
	mu     sync.Mutex
	opened int
}

func (c *counting) Open(s store.Sealed, b store.Binding) ([]byte, error) {
	c.mu.Lock()
	c.opened++
	c.mu.Unlock()
	return c.Sealer.Open(s, b)
}

func (c *counting) opens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opened
}

// logs is a log sink a server and a test share.
type logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// rig is one carrier over the memory store against the stub API, the stub
// authorization server and, where git is installed, the stub git host.
type rig struct {
	t      *testing.T
	c      *Carrier
	srv    *httptest.Server
	st     *memory.Store
	sealer *counting
	az     *decider
	api    *stubs.API
	auth   *stubs.AuthServer
	git    *stubs.GitHost
	conns  map[string]signin.Connector
	logs   *logs
	// serving counts the requests the carrier has not finished, whose
	// records are written after their answers.
	serving inflight
}

// inflight counts requests in flight, and waits for none.
type inflight struct{ n atomic.Int64 }

func (f *inflight) Add(d int64) { f.n.Add(d) }
func (f *inflight) Done()       { f.n.Add(-1) }

// Wait waits until no request is in flight.
func (f *inflight) Wait() {
	for f.n.Load() > 0 {
		time.Sleep(5 * time.Millisecond)
	}
}

// clientSecret is the secret of the catalog's oauth client.
const clientSecret = "the-catalog-client-secret"

func newRig(t *testing.T, withGit bool) *rig {
	t.Helper()
	r := &rig{t: t, st: memory.New(memory.Options{}), az: &decider{}, api: stubs.NewAPI(t), auth: stubs.NewAuthServer(t), logs: &logs{}}
	ports := []int{r.api.Port(), r.auth.Port()}
	gitURL := r.api.URL()
	if withGit {
		r.git = stubs.NewGitHost(t)
		if err := r.git.Seed("acme/app.git"); err != nil {
			t.Fatal(err)
		}
		ports = append(ports, r.git.Port())
		gitURL = r.git.URL()
	}
	r.auth.AddClient("pons-client", clientSecret)
	sealer, err := store.NewSealer([32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	r.sealer = &counting{Sealer: sealer}
	doc := `connectors:
  - name: api
    title: API
    kind: http
    url: ` + r.api.URL() + `
    hosts: ["api.example.com", "git.example.com"]
    git: {url: "` + gitURL + `", inject: {scheme: basic, username: x-access-token}}
    http: {read_only: ["POST /search/*"], pass: [X-Api-Version], pass_back: ["X-RateLimit-*"]}
    auth: {type: token}
  - name: signed
    title: Signed
    kind: http
    url: ` + r.api.URL() + `
    hosts: ["api.example.com", "git.example.com"]
    git: {url: "` + gitURL + `"}
    auth:
      type: oauth
      discovery: none
      authorize_url: ` + r.auth.AuthorizeURL() + `
      token_url: ` + r.auth.TokenURL() + `
      client: {id: pons-client, secret: {env: CLIENT_SECRET}}
  - name: minted
    title: Minted
    kind: http
    url: ` + r.api.URL() + `
    auth: {type: client_credentials, token_url: "` + r.auth.TokenURL() + `", scopes: [read]}
  - name: open
    title: Open
    kind: http
    url: ` + r.api.URL() + `
    auth: {type: none}
  - name: tools
    title: Tools
    kind: mcp
    url: ` + r.api.URL() + `/mcp
    auth: {type: none}
`
	lookup := func(name string) (string, bool) { return clientSecret, name == "CLIENT_SECRET" }
	cat, err := catalog.Parse([]byte(doc), catalog.Options{LookupEnv: lookup})
	if err != nil {
		t.Fatal(err)
	}
	r.conns = map[string]signin.Connector{}
	for _, c := range cat.Connectors {
		r.conns[c.Name] = signin.Connector{Connector: c, Ref: c.Name}
	}
	resolve := func(_ context.Context, ref string) (signin.Connector, error) {
		if c, ok := r.conns[ref]; ok {
			return c, nil
		}
		return signin.Connector{}, signin.ErrNoConnector
	}
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	outside := dial.New(dial.Options{Resolver: stubs.Resolver(), Roots: stubs.Roots(), Permit: stubs.Permit(ports...)})
	sign := &signin.Signin{Store: r.st, Sealer: r.sealer, Dial: outside, Resolve: resolve, LookupEnv: lookup,
		PublicURL: "https://pons.example.com", BasePath: "/v1", Log: log}
	r.c = &Carrier{
		Store: r.st, Sealer: r.sealer, Auth: bearers{}, Authz: r.az, Dial: outside, Signin: sign, Resolve: resolve,
		BasePath: "/v1", ReturnURLs: []string{"https://app.example.com/back"},
		MaxForwardBytes: 1 << 20, HeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		MaxInflight: 64, MaxInflightPerSubject: 32, Log: log,
	}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.serving.Add(1)
		defer r.serving.Done()
		if !r.c.Handles(req) {
			http.NotFound(w, req)
			return
		}
		r.c.ServeHTTP(w, req)
	}))
	t.Cleanup(r.srv.Close)
	r.c.PublicURL = r.srv.URL
	return r
}

// connect stores a connection of a connector for an owner, with its
// credential sealed as a connect or a confirm would.
func (r *rig) connect(owner, connector string, secrets store.Secrets, meta store.Meta) store.Connection {
	r.t.Helper()
	conn := r.conns[connector]
	c := store.Connection{
		ID: "con_" + strings.ToLower(strings.ReplaceAll(r.t.Name()+connector+owner, "/", "")), Owner: subject(owner),
		Name: connector, Connector: connector, Kind: conn.Kind, Auth: conn.Auth.Type, State: store.StateConnected, CreatedBy: subject(owner),
	}
	c.ID = strings.Map(func(ch rune) rune {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' {
			return ch
		}
		return -1
	}, c.ID)
	ctx := context.Background()
	if err := r.st.Connections().Create(ctx, c, 0); err != nil {
		r.t.Fatal(err)
	}
	if conn.Auth.Type == catalog.AuthNone {
		return c
	}
	r.put(c, secrets, meta)
	return c
}

// put seals and writes a connection's credential.
func (r *rig) put(c store.Connection, secrets store.Secrets, meta store.Meta) {
	r.t.Helper()
	plain, err := secrets.Encode()
	if err != nil {
		r.t.Fatal(err)
	}
	doc, err := store.EncodeMeta(meta)
	if err != nil {
		r.t.Fatal(err)
	}
	sealed, err := r.sealer.Seal(plain, store.CredentialBinding(c.ID, c.Owner, c.Auth, meta, ""))
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.st.Credentials().Put(context.Background(), c.ID, store.SealedCredential{Kind: c.Auth, Meta: doc, Sealed: sealed}); err != nil {
		r.t.Fatal(err)
	}
}

// keyed is a token connection of alice's to the api connector.
func (r *rig) keyed() store.Connection {
	return r.connect("alice", "api", store.Secrets{Value: "the-key-of-alice-0001"}, store.Meta{Header: "Authorization", Format: "Bearer {value}"})
}

// signedIn is an oauth connection of alice's whose tokens the stub issued.
func (r *rig) signedIn(expires time.Time) (store.Connection, string) {
	access, refresh := r.auth.Grant("pons-client", "read")
	return r.connect("alice", "signed", store.Secrets{AccessToken: access, RefreshToken: refresh}, store.Meta{
		TokenType: "Bearer", AccessExpiresAt: expires, Issuer: "", TokenEndpoint: r.auth.TokenURL(), ClientID: "pons-client",
	}), access
}

// answer is one response of the carrier.
type answer struct {
	status int
	header http.Header
	body   []byte
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

// send sends one request with the path exactly as written, its escapes and
// dot segments kept, as the bearer, or none for "".
func (r *rig) send(method, path, bearer string, body io.Reader, headers ...string) answer {
	r.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, r.srv.URL+"/", body)
	if err != nil {
		r.t.Fatal(err)
	}
	p, q, _ := strings.Cut(path, "?")
	req.URL.Opaque, req.URL.RawQuery = p, q
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	client := *r.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		r.t.Fatal(err, cerr)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

// address is the path of a connection's address.
func address(c store.Connection, kind string) string { return "/v1/connections/" + c.ID + "/" + kind }

// calls are the records of a connection, oldest first, once every request
// served has ended.
func (r *rig) calls(c store.Connection) []store.Call {
	r.t.Helper()
	r.serving.Wait()
	got, _, err := r.st.Calls().List(context.Background(), c.ID, store.Page{Limit: 200})
	if err != nil {
		r.t.Fatal(err)
	}
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	return got
}

// gitRun runs a git client in a directory, against the carrier, with the
// caller's bearer in every request.
func gitRun(t *testing.T, dir, bearer string, args ...string) (string, error) {
	t.Helper()
	out, err := gitCommand(t, dir, bearer, args...).CombinedOutput()
	return string(out), err
}

// gitStderr runs a git client as gitRun does and answers what it printed on
// its standard error alone.
func gitStderr(t *testing.T, dir, bearer string, args ...string) (string, error) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := gitCommand(t, dir, bearer, args...)
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

// gitCommand is a git client with the caller's bearer in every request and
// nothing of the machine's configuration.
func gitCommand(t *testing.T, dir, bearer string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), gitBinary(t), append([]string{"-c", "http.extraHeader=Authorization: Bearer " + bearer}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "none"), "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Agent", "GIT_AUTHOR_EMAIL=agent@example.com", "GIT_COMMITTER_NAME=Agent", "GIT_COMMITTER_EMAIL=agent@example.com")
	return cmd
}

// gitBinary is the git a test runs, or a skip with the reason.
func gitBinary(t *testing.T) string {
	t.Helper()
	path, err := stubs.GitPath()
	if err != nil {
		t.Skip(err.Error())
	}
	return path
}
