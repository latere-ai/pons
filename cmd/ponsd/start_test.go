// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/internal/store/postgres/pgtest"
	"latere.ai/x/pons/test/stubs"
)

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

func writeCatalog(t testing.TB, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := writeFile(path, doc); err != nil {
		t.Fatal(err)
	}
	return path
}

func mapsWith(m map[string]string, k, v string) map[string]string {
	out := maps.Clone(m)
	out[k] = v
	return out
}

// startErr runs serve with the environment and answers its error, or nil
// once it listens, which stops it.
func startErr(t testing.TB, over map[string]string) (*syncBuffer, error) {
	t.Helper()
	env := environment(t, stubs.NewIssuer(t), over)
	logs := &syncBuffer{}
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	roots := stubs.Roots()
	go func() {
		done <- serve(ctx, func(k string) string { return env[k] }, logs, Hooks{Ready: ready, Roots: roots})
	}()
	select {
	case <-ready:
		cancel()
		if err := <-done; err != nil {
			t.Errorf("stopping: %v", err)
		}
		return logs, nil
	case err := <-done:
		return logs, err
	case <-time.After(60 * time.Second):
		t.Fatal("serve neither listened nor stopped")
	}
	return logs, nil
}

// firstLine is the message of a log's first line.
func firstLine(logs string) string {
	line, _, _ := strings.Cut(logs, "\n")
	return line
}

// With no database configured the server starts on the memory store and
// says so in its first log line; with one configured and unreachable it
// does not start.
func TestStoreSelection(t *testing.T) {
	logs, err := startErr(t, nil)
	if err != nil || !strings.Contains(firstLine(logs.String()), "store: memory") {
		t.Fatalf("no database: %v\n%s", err, logs)
	}
	db := database(t)
	logs, err = startErr(t, db)
	if err != nil || !strings.Contains(firstLine(logs.String()), "store: postgres") {
		t.Fatalf("a database: %v\n%s", err, logs)
	}
	if logs, err := startErr(t, map[string]string{"PONS_CATALOG_FILE": ""}); err != nil || !strings.Contains(logs.String(), "catalog: empty") {
		t.Fatalf("no catalog: %v\n%s", err, logs)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	gone := map[string]string{"PONS_DATABASE_URL": "postgres://pons:pons@" + closed + "/pons?connect_timeout=2", "PONS_PUBLIC_URL": "https://pons.example.com"}
	_, err = startErr(t, gone)
	if err == nil || !strings.Contains(err.Error(), "PONS_DATABASE_URL") || strings.Contains(err.Error(), closed) {
		t.Fatalf("an unreachable database: %v", err)
	}
	pool := mapsWith(db, "PONS_DATABASE_POOL_URL", "postgres://pons:pons@"+closed+"/pons?connect_timeout=2")
	if _, err := startErr(t, pool); err == nil || !strings.Contains(err.Error(), "PONS_DATABASE_POOL_URL") || strings.Contains(err.Error(), closed) {
		t.Fatalf("an unreachable pool: %v", err)
	}
}

// Each case of the table of refusals of spec 011 stops serve before it
// listens, and PONS_PUBLIC_URL over http is accepted on the memory store
// alone.
func TestStartRefusals(t *testing.T) {
	db := database(t)
	ahead := database(t)
	if err := pgtest.Exec(context.Background(), ahead["PONS_DATABASE_URL"], "UPDATE schema_migrations SET version = 9999"); err != nil {
		t.Fatal(err)
	}
	dirty := database(t)
	if err := pgtest.Exec(context.Background(), dirty["PONS_DATABASE_URL"], "UPDATE schema_migrations SET dirty = true"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		over  map[string]string
		names string
	}{
		"no public url":           {map[string]string{"PONS_PUBLIC_URL": ""}, "PONS_PUBLIC_URL"},
		"no issuer":               {map[string]string{"PONS_OIDC_ISSUERS": ""}, "PONS_OIDC_ISSUERS"},
		"http with a database":    {mapsWith(db, "PONS_PUBLIC_URL", "http://pons.example.com"), "PONS_PUBLIC_URL"},
		"no key with a database":  {mapsWith(db, "PONS_SEALING_KEYS", ""), "PONS_SEALING_KEYS"},
		"a schema ahead":          {ahead, "9999"},
		"a dirty schema":          {dirty, "dirty"},
		"a catalog that is wrong": {map[string]string{"PONS_CATALOG_FILE": writeCatalog(t, "connectors:\n  - name: Bad_Name\n")}, `connectors[0] "Bad_Name"`},
		"a catalog that is gone":  {map[string]string{"PONS_CATALOG_FILE": filepath.Join(t.TempDir(), "none.yaml")}, "catalog"},
		"no token file":           {map[string]string{"PONS_AUTHORIZER_URL": "https://authz.example.com"}, "PONS_AUTHORIZER_TOKEN_FILE"},
		"a malformed key":         {map[string]string{"PONS_SEALING_KEYS": key(1) + ",not-a-key"}, "position 2"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := startErr(t, tc.over)
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("want a refusal naming %q, got %v", tc.names, err)
			}
		})
	}
	if _, err := startErr(t, map[string]string{"PONS_PUBLIC_URL": "http://localhost:8080"}); err != nil {
		t.Fatalf("http on the memory store: %v", err)
	}
}

// A server that lists no issuer does not start and names the variable.
func TestAServerWithNoIssuerIsRefused(t *testing.T) {
	_, err := startErr(t, map[string]string{"PONS_OIDC_ISSUERS": ""})
	if err == nil || !strings.Contains(err.Error(), "PONS_OIDC_ISSUERS") {
		t.Fatalf("%v", err)
	}
	var out bytes.Buffer
	env := map[string]string{"PONS_PUBLIC_URL": "http://localhost"}
	if err := check(context.Background(), func(k string) string { return env[k] }, &out, Hooks{}); err == nil || !strings.Contains(err.Error(), "PONS_OIDC_ISSUERS") {
		t.Fatalf("check: %v", err)
	}
}

// An authorizer URL with no readable, non-empty token file stops the start,
// naming the variable.
func TestAnAuthorizerNeedsItsTokenFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := writeFile(empty, "\n"); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"", empty, filepath.Join(t.TempDir(), "none")} {
		_, err := startErr(t, map[string]string{"PONS_AUTHORIZER_URL": "https://authz.example.com", "PONS_AUTHORIZER_TOKEN_FILE": file})
		if err == nil || !strings.Contains(err.Error(), "PONS_AUTHORIZER_TOKEN_FILE") {
			t.Errorf("%q: %v", file, err)
		}
	}
}

// A server is refused an endpoint that allows the probe; one that does not
// answer is named and the server starts.
func TestTheServerRefusesAnEndpointThatAllowsTheProbe(t *testing.T) {
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, `{"allow": true}`); err != nil {
			t.Error(err)
		}
	}))
	defer open.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := writeFile(token, "bearer-of-the-test"); err != nil {
		t.Fatal(err)
	}
	_, err := startErr(t, map[string]string{"PONS_AUTHORIZER_URL": open.URL, "PONS_AUTHORIZER_TOKEN_FILE": token})
	if err == nil || !strings.Contains(err.Error(), "allowed the probe") {
		t.Fatalf("an endpoint that allows the probe: %v", err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	logs, err := startErr(t, map[string]string{"PONS_AUTHORIZER_URL": gone.URL, "PONS_AUTHORIZER_TOKEN_FILE": token})
	if err != nil || !strings.Contains(logs.String(), "did not answer the probe") || !strings.Contains(logs.String(), "decides: authorizer") {
		t.Fatalf("an endpoint that does not answer: %v\n%s", err, logs)
	}
	var out bytes.Buffer
	env := environment(t, stubs.NewIssuer(t), map[string]string{"PONS_AUTHORIZER_URL": open.URL, "PONS_AUTHORIZER_TOKEN_FILE": token})
	if err := check(context.Background(), func(k string) string { return env[k] }, &out, Hooks{}); err == nil {
		t.Fatal("check passed an endpoint that allows the probe")
	}
}

// An issuer that does not answer at start is named, and the server starts.
func TestAnIssuerThatDoesNotAnswerIsNamed(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	logs, err := startErr(t, map[string]string{"PONS_OIDC_ISSUERS": gone.URL})
	if err != nil || !strings.Contains(logs.String(), "an issuer did not answer") {
		t.Fatalf("%v\n%s", err, logs)
	}
}

// runCheck runs ponsd check with the environment.
func runCheck(t testing.TB, env map[string]string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	roots := stubs.Roots()
	// The check of an environment that names the stub issuer needs its
	// roots, which only a test hands it.
	err := check(context.Background(), func(k string) string { return env[k] }, &out, Hooks{Roots: roots})
	return out.String(), err
}

// ponsd check fails on what serve refuses, and reports the dial switch and
// the proxy with a zero status.
func TestCheckReports(t *testing.T) {
	iss := stubs.NewIssuer(t)
	if _, err := runCheck(t, environment(t, iss, map[string]string{"PONS_PUBLIC_URL": ""})); err == nil {
		t.Fatal("check passed what serve refuses")
	}
	var plain bytes.Buffer
	env := environment(t, iss, nil)
	if err := run(context.Background(), []string{"check"}, func(k string) string { return env[k] }, &plain, io.Discard); err != nil || !strings.Contains(plain.String(), "configuration: ok") {
		t.Fatalf("ponsd check: %v %s", err, plain.String())
	}
	out, err := runCheck(t, environment(t, iss, map[string]string{"PONS_DIAL_ALLOW_PRIVATE": "1", "PONS_OUTBOUND_PROXY": "http://user:secret-of-the-proxy@proxy.example.com:3128"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"configuration: ok", "catalog: 6 connectors", "decides: owner policy", "dial: private addresses allowed", "dial: requests leave through a proxy"} {
		if !strings.Contains(out, want) {
			t.Errorf("check does not report %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret-of-the-proxy") || strings.Contains(out, "user:") {
		t.Fatalf("check printed the proxy's user: %s", out)
	}
	if strings.Contains(out, "sealing:") {
		t.Fatal("check counted sealed values on the memory store")
	}
	if _, err := runCheck(t, environment(t, iss, map[string]string{"PONS_CATALOG_FILE": writeCatalog(t, "nonsense: 1\n")})); err == nil || !strings.Contains(err.Error(), "catalog") {
		t.Fatalf("check passed a catalog that does not load: %v", err)
	}
	roots := stubs.Roots()
	env = environment(t, iss, nil)
	if err := check(context.Background(), func(k string) string { return env[k] }, failingWriter{}, Hooks{Roots: roots}); err == nil {
		t.Fatal("check printed into a writer that fails and said nothing")
	}
}

// ponsd check reports the values not under the first sealing key, and
// exits non-zero for one under no listed key.
func TestCheckReportsWhatRemains(t *testing.T) {
	iss := stubs.NewIssuer(t)
	db := database(t)
	s := startStack(t, iss, db)
	s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0012"})
	s.stop()

	rotated := mapsWith(s.env, "PONS_SEALING_KEYS", key(2)+","+key(1))
	out, err := runCheck(t, rotated)
	if err != nil || !strings.Contains(out, "sealing: credentials: 1 not under the first key, 0 under no listed key") {
		t.Fatalf("after a key is prepended: %v\n%s", err, out)
	}
	lost := mapsWith(s.env, "PONS_SEALING_KEYS", key(3))
	out, err = runCheck(t, lost)
	if err == nil || !strings.Contains(out, "sealing: credentials: 0 not under the first key, 1 under no listed key") {
		t.Fatalf("with the key gone: %v\n%s", err, out)
	}
	// serve rewraps in the background, and the next check finds nothing
	// left.
	again := startStack(t, iss, rotated)
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(again.logs.String(), "rewrapped under the first sealing key") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	again.stop()
	out, err = runCheck(t, rotated)
	if err != nil || !strings.Contains(out, "sealing: credentials: 0 not under the first key, 0 under no listed key") {
		t.Fatalf("after the rewrap: %v\n%s", err, out)
	}
}

// With PONS_DIAL_ALLOW_PRIVATE=1 the start logs a warning, and ponsd check
// and /readyz report it. That a stub on loopback is refused without it is
// the carrier's to show.
func TestAllowPrivateIsLoud(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_DIAL_ALLOW_PRIVATE": "1"})
	if !strings.Contains(s.logs.String(), `"level":"WARN","msg":"dial: private addresses allowed`) {
		t.Fatalf("no warning:\n%s", s.logs)
	}
	if a := s.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusOK || !strings.Contains(string(a.body), "dial: private addresses allowed") {
		t.Fatalf("/readyz: %d %s", a.status, a.body)
	}
	out, err := runCheck(t, s.env)
	if err != nil || !strings.Contains(out, "dial: private addresses allowed") {
		t.Fatalf("check: %v %s", err, out)
	}
	quiet := startStack(t, stubs.NewIssuer(t), nil)
	if a := quiet.do(http.MethodGet, "/readyz", "", nil); strings.Contains(string(a.body), "dial") {
		t.Fatalf("/readyz without the switch: %s", a.body)
	}
}

// relay forwards TCP to a target and can be cut and restored, standing for
// a database that goes away and comes back.
type relay struct {
	t      testing.TB
	target string
	addr   string
	mu     sync.Mutex
	ln     net.Listener
	conns  []net.Conn
}

func newRelay(t testing.TB, target string) *relay {
	r := &relay{t: t, target: target}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	r.serve(ln)
	t.Cleanup(r.cut)
	return r
}

func (r *relay) serve(ln net.Listener) {
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", r.target)
			if err != nil {
				r.t.Logf("the relay could not reach its target: %v", err)
				if err := c.Close(); err != nil {
					r.t.Logf("closing: %v", err)
				}
				continue
			}
			r.mu.Lock()
			r.conns = append(r.conns, c, up)
			r.mu.Unlock()
			go pipe(c, up)
			go pipe(up, c)
		}
	}()
}

func pipe(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return
	}
}

// cut closes the listener and every connection.
func (r *relay) cut() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		if err := r.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.t.Logf("closing the relay: %v", err)
		}
	}
	for _, c := range r.conns {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.t.Logf("closing a relayed connection: %v", err)
		}
	}
	r.conns = nil
}

// restore listens again on the same address.
func (r *relay) restore() {
	ln, err := net.Listen("tcp", r.addr)
	if err != nil {
		r.t.Fatal(err)
	}
	r.serve(ln)
}

// /readyz fails naming the store while the database is unreachable and
// recovers without a restart, fails naming sealing with no key, and
// carries the dial line while the switch is set.
func TestReadiness(t *testing.T) {
	db := database(t)
	direct := db["PONS_DATABASE_URL"]
	host := strings.TrimPrefix(direct[strings.Index(direct, "@")+1:], "")
	host, _, _ = strings.Cut(host, "/")
	r := newRelay(t, host)
	db["PONS_DATABASE_POOL_URL"] = strings.Replace(direct, host, r.addr, 1)
	s := startStack(t, stubs.NewIssuer(t), db, 50*time.Millisecond)
	if a := s.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusOK {
		t.Fatalf("ready: %d %s", a.status, a.body)
	}
	r.cut()
	cut := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.logs.String(), "a sweep failed") && time.Now().Before(cut) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(s.logs.String(), "a sweep failed") {
		t.Fatalf("a sweep without its database logged nothing:\n%s", s.logs)
	}
	a := s.do(http.MethodGet, "/readyz", "", nil)
	if a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "store") || strings.Contains(string(a.body), r.addr) {
		t.Fatalf("with the database gone: %d %s", a.status, a.body)
	}
	r.restore()
	deadline := time.Now().Add(20 * time.Second)
	for {
		a = s.do(http.MethodGet, "/readyz", "", nil)
		if a.status == http.StatusOK || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if a.status != http.StatusOK {
		t.Fatalf("the database came back and the server is not ready: %d %s", a.status, a.body)
	}
	nokey := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_SEALING_KEYS": ""})
	if a := nokey.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "sealing") {
		t.Fatalf("no key: %d %s", a.status, a.body)
	}
}

// Every replica sweeps records past their retention on its tick.
func TestTheServerSweeps(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_RECORDS_RETENTION": "1h"}, 20*time.Millisecond)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.logs.String(), `"msg":"swept"`) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(s.logs.String(), `"msg":"swept"`) {
		t.Fatalf("no sweep ran:\n%s", s.logs)
	}
}

// An address the server cannot listen on stops the start, naming the
// variable.
func TestAnAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := startErr(t, map[string]string{"PONS_ADDR": ln.Addr().String()}); err == nil || !strings.Contains(err.Error(), "PONS_ADDR") {
		t.Fatalf("%v", err)
	}
}

// failingWriter refuses every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the writer is closed") }

// A request still open when its grace ends is closed, and the server stops.
func TestAStopClosesWhatOutlivesTheGrace(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil, 0, 100*time.Millisecond)
	conn, err := net.Dial("tcp", strings.TrimPrefix(s.base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	req := "POST /v1/connections HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + s.iss.Token("alice", nil) +
		"\r\nContent-Length: 1000\r\n\r\n{"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	done := make(chan struct{})
	go func() { s.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the server waited past its grace")
	}
}

// A malformed or repeated sealing key stops the start, naming its position
// and never a key.
func TestAMalformedKeyStopsTheStart(t *testing.T) {
	for _, keys := range []string{key(1) + ",not-a-key-of-32-bytes", key(1) + "," + key(1)} {
		_, err := startErr(t, map[string]string{"PONS_SEALING_KEYS": keys})
		if err == nil || !strings.Contains(err.Error(), "position 2") || strings.Contains(err.Error(), key(1)) || strings.Contains(err.Error(), "not-a-key") {
			t.Errorf("%v", err)
		}
	}
}

// A refusal of an address answers the code of its route with its rule's
// name as details.reason, and no member of the answer holds the address.
// At an add, the rules before a name is resolved answer 400; the refusals
// of the dialer at discovery wait for the sign-in.
func TestRefusalsNameTheRuleAndNoAddress(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	for address, rule := range map[string]string{
		"http://wiki.example.com/mcp":       "scheme_not_https",
		"https://169.254.169.254/mcp":       "host_not_a_name",
		"https://0x7f.1/mcp":                "host_not_a_name",
		"https://wiki.internal/mcp":         "host_not_a_name",
		"https://wiki.example.com:6443/mcp": "port_not_allowed",
	} {
		a := s.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
			"name": "wiki", "title": "Wiki", "kind": "mcp", "url": address, "auth": map[string]any{"type": "none"},
		})
		host := strings.TrimPrefix(strings.TrimPrefix(address, "https://"), "http://")
		host, _, _ = strings.Cut(host, "/")
		if a.status != http.StatusBadRequest || a.code() != "invalid_field" || a.detail("field") != "url" || a.detail("reason") != rule || strings.Contains(string(a.body), host) {
			t.Errorf("%s: %d %s", address, a.status, a.body)
		}
	}
}
