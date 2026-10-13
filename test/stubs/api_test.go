// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

// outside is the dialer a server under test runs, pointed at the stubs on
// the ports given.
func outside(ports ...int) *dial.Client {
	return dial.New(dial.Options{Resolver: stubs.Resolver(), Roots: stubs.Roots(), Permit: stubs.Permit(ports...)})
}

// send sends one request through the dialer and reads the answer.
func send(t *testing.T, c *dial.Client, method, url, credential string, body io.Reader) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	var secrets []dial.Secret
	if credential != "" {
		secrets = append(secrets, dial.Secret{Value: credential, Header: "Authorization", Hosts: catalog.Matcher([]string{"*.example.com"})})
	}
	resp, err := c.Do(t.Context(), dial.Request{HTTP: req, Secrets: secrets})
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	return resp.StatusCode, resp.Header, raw
}

// The stub API answers its routes by its name through the dialer, records
// the credential each request carried, and changes one answer per switch.
func TestAPIServesACodeHostsRoutes(t *testing.T) {
	api := stubs.NewAPI(t)
	if !strings.HasPrefix(api.URL(), "https://api.example.com:") {
		t.Fatalf("the stub is not named: %s", api.URL())
	}
	c := outside(api.Port())
	if status, _, body := send(t, c, http.MethodGet, api.URL()+"/", "Bearer one-credential", nil); status != http.StatusOK || !bytes.Contains(body, []byte("current_user_url")) {
		t.Fatalf("root %d %s", status, body)
	}
	api.SetLogin("someone")
	if _, _, body := send(t, c, http.MethodGet, api.URL()+"/user", "", nil); !bytes.Contains(body, []byte(`"login":"someone"`)) {
		t.Fatalf("user %s", body)
	}
	_, h, body := send(t, c, http.MethodGet, api.URL()+"/repos/acme/app/issues", "", nil)
	if !strings.Contains(h.Get("Link"), api.URL()+"/repos/acme/app/issues?page=2") || !bytes.Contains(body, []byte(api.URL())) {
		t.Fatalf("issues %v %s", h, body)
	}
	if status, _, body := send(t, c, http.MethodPost, api.URL()+"/repos/acme/app/issues", "", strings.NewReader(`{"title":"x"}`)); status != http.StatusCreated || !bytes.Contains(body, []byte(`"number":2`)) {
		t.Fatalf("a write %d %s", status, body)
	}
	if got := api.Requests(); len(got) != 4 || string(got[3].Body) != `{"title":"x"}` || got[0].Credential != "Bearer one-credential" {
		t.Fatalf("recorded %+v", got)
	}
	_, h, _ = send(t, c, http.MethodGet, api.URL()+"/headers", "", nil)
	for _, name := range []string{"Set-Cookie", "WWW-Authenticate", "ETag", "Retry-After", "X-Ratelimit-Remaining", "X-Stub-Private"} {
		if h.Get(name) == "" {
			t.Errorf("/headers lacks %s", name)
		}
	}
	if _, _, body := send(t, c, http.MethodGet, api.URL()+"/large?bytes=100000", "", nil); len(body) != 100000 {
		t.Fatalf("large %d", len(body))
	}
	if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/large?bytes=x", "", nil); status != http.StatusBadRequest {
		t.Fatalf("large of no count %d", status)
	}
	if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/nothing", "", nil); status != http.StatusNotFound {
		t.Fatalf("an unknown route %d", status)
	}
	if status, _, body := send(t, c, http.MethodPut, api.URL()+"/upload", "", strings.NewReader(strings.Repeat("u", 10000))); status != http.StatusOK || !bytes.Contains(body, []byte(`"bytes":10000`)) || api.Received() != 10000 {
		t.Fatalf("upload %d %s %d", status, body, api.Received())
	}
	// A redirect within is followed by a request that follows them; one
	// elsewhere is refused by a request that follows none.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.URL()+"/redirect/within", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(t.Context(), dial.Request{HTTP: req, Redirects: 3})
	if err != nil || resp.Request.URL.Path != "/user" {
		t.Fatalf("within: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, api.URL()+"/redirect/elsewhere", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(t.Context(), dial.Request{HTTP: req}); err == nil {
		t.Fatal("a redirect elsewhere is followed")
	}
}

// Each switch of the stub API changes one answer.
func TestEachAPISwitchChangesOneAnswer(t *testing.T) {
	api := stubs.NewAPI(t, stubs.WithAPIName("other.example.com"))
	c := outside(api.Port())
	api.Refuse("Bearer old")
	if status, h, _ := send(t, c, http.MethodGet, api.URL()+"/user", "Bearer old", nil); status != http.StatusUnauthorized || h.Get("WWW-Authenticate") == "" {
		t.Fatalf("a refused credential %d", status)
	}
	if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/user", "Bearer new", nil); status != http.StatusOK {
		t.Fatalf("another credential %d", status)
	}
	api.Refuse()
	if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/user", "Bearer new", nil); status != http.StatusUnauthorized {
		t.Fatalf("every credential refused %d", status)
	}
	api.Accept()
	api.Slow(150 * time.Millisecond)
	start := time.Now()
	send(t, c, http.MethodGet, api.URL()+"/user", "", nil)
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("a slow answer is not slow")
	}
	api.Slow(0)
	api.Protect([]string{"read", "write"}, "https://auth.example.com")
	status, h, _ := send(t, c, http.MethodGet, api.URL()+"/", "", nil)
	if challenge := h.Get("WWW-Authenticate"); status != http.StatusUnauthorized || !strings.Contains(challenge, `resource_metadata="`+api.URL()+`/.well-known/oauth-protected-resource"`) || !strings.Contains(challenge, `scope="read write"`) {
		t.Fatalf("protected %d %q", status, challenge)
	}
	_, _, body := send(t, c, http.MethodGet, api.URL()+"/.well-known/oauth-protected-resource", "", nil)
	var doc struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Resource != api.URL() || len(doc.Servers) != 1 {
		t.Fatalf("metadata %s %v", body, err)
	}
	if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/", "Bearer any", nil); status != http.StatusOK {
		t.Fatalf("a protected resource with a credential %d", status)
	}
	api.Protect(nil)
	api.Insufficient([]string{"repo", "admin"})
	if status, h, _ := send(t, c, http.MethodGet, api.URL()+"/user", "Bearer any", nil); status != http.StatusForbidden || !strings.Contains(h.Get("WWW-Authenticate"), `scope="repo admin"`) {
		t.Fatalf("an insufficient scope %d %v", status, h)
	}
	api.Insufficient(nil)
	if status, h, body := send(t, c, http.MethodGet, api.URL()+"/stream?chunks=3&gap=1ms", "Bearer any", nil); status != http.StatusOK || h.Get("Content-Type") != "text/event-stream" || strings.Count(string(body), "data:") != 3 {
		t.Fatalf("a stream %d %s", status, body)
	}
	for _, q := range []string{"chunks=x&gap=1ms", "chunks=1&gap=x"} {
		if status, _, _ := send(t, c, http.MethodGet, api.URL()+"/stream?"+q, "Bearer any", nil); status != http.StatusBadRequest {
			t.Fatalf("a stream of %s: %d", q, status)
		}
	}
	// A slow answer that the caller abandons ends with the caller.
	api.Slow(time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.URL()+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, dial.Request{HTTP: req}); err == nil {
		t.Fatal("an abandoned request answered")
	}
}

// The resolver answers loopback for a name under example.com and fails
// any other, and the permit admits the ports given on loopback alone.
func TestResolverAndPermit(t *testing.T) {
	r := stubs.Resolver()
	if got, err := r.LookupNetIP(t.Context(), "ip", "API.Example.com."); err != nil || len(got) != 1 || !got[0].IsLoopback() {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := r.LookupNetIP(t.Context(), "ip", "elsewhere.example.net"); err == nil {
		t.Fatal("a name outside example.com resolves")
	}
	p := stubs.Permit(8443)
	if !p(netip.MustParseAddr("127.0.0.1"), 8443) || p(netip.MustParseAddr("127.0.0.1"), 8444) || p(netip.MustParseAddr("10.0.0.1"), 8443) {
		t.Fatal("the permit admits what it should not")
	}
}

// The stub git host serves a real git client: a clone, a push of a branch,
// a deletion, with the credential recorded and the refusal switch.
func TestGitHostServesGit(t *testing.T) {
	g := stubs.NewGitHost(t)
	if err := g.Seed("acme/app.git"); err != nil {
		t.Fatal(err)
	}
	// git reaches the stub on loopback by its address: the name needs a
	// resolver git does not take, and the certificate covers 127.0.0.1.
	local := strings.Replace(g.URL(), "git.example.com", "127.0.0.1", 1)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, stubs.AuthorityPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), gitBinary(t), append([]string{"-c", "http.sslCAInfo=" + ca, "-c", "http.extraHeader=Authorization: Basic c3R1Yjp0b2tlbg=="}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "none"), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	git("clone", "--quiet", local+"/acme/app.git", "app")
	dir = filepath.Join(dir, "app")
	git("push", "--quiet", "origin", "HEAD:refs/heads/agents/one")
	refs, err := g.Refs("acme/app.git")
	if err != nil || refs["refs/heads/agents/one"] == "" || refs["refs/heads/main"] == "" {
		t.Fatalf("refs %v %v", refs, err)
	}
	git("push", "--quiet", "origin", ":refs/heads/agents/one")
	if refs, err := g.Refs("acme/app.git"); err != nil || refs["refs/heads/agents/one"] != "" {
		t.Fatalf("a deleted ref %v %v", refs, err)
	}
	for _, cred := range g.Credentials() {
		if cred != "Basic c3R1Yjp0b2tlbg==" {
			t.Fatalf("a request carried %q", cred)
		}
	}
	if len(g.Requests()) < 4 {
		t.Fatalf("requests %+v", g.Requests())
	}
	g.Refuse(true)
	cmd := exec.CommandContext(t.Context(), gitBinary(t), "-c", "http.sslCAInfo="+ca, "ls-remote", local+"/acme/app.git")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("a refusing host answered: %s", out)
	}
	if err := g.Seed("acme/app.git"); err == nil {
		t.Fatal("seeding a repository twice succeeds")
	}
	if _, err := g.Refs("acme/none.git"); err == nil {
		t.Fatal("the refs of no repository")
	}
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
