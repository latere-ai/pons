// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
)

// An http URL, a URL with a user, an IPv4 literal in each notation, an IPv6
// literal, a single label, localhost and a name under each reserved suffix
// are refused with no name resolved.
func TestChecksBeforeResolving(t *testing.T) {
	res := newResolver()
	c := New(Options{Resolver: res})
	cases := map[string]string{
		"http://svc.example.com/mcp":         SchemeNotHTTPS,
		"ftp://svc.example.com/":             SchemeNotHTTPS,
		"https://user@svc.example.com/":      SchemeNotHTTPS,
		"https://user:pass@svc.example.com/": SchemeNotHTTPS,
		"https://127.0.0.1/":                 HostNotAName,
		"https://10.1/":                      HostNotAName,
		"https://0x7f.1/":                    HostNotAName,
		"https://0x7f000001/":                HostNotAName,
		"https://2130706433/":                HostNotAName,
		"https://017700000001/":              HostNotAName,
		"https://[::1]/":                     HostNotAName,
		"https://[fe80::1%25en0]/":           HostNotAName,
		"https://intranet/":                  HostNotAName,
		"https://localhost/":                 HostNotAName,
		"https://api.localhost/":             HostNotAName,
		"https://printer.local/":             HostNotAName,
		"https://db.internal/":               HostNotAName,
		"https://router.home.arpa/":          HostNotAName,
		"https://LOCALHOST./":                HostNotAName,
		"https://svc.example.com:99999/":     PortNotAllowed,
		"https://svc.example.com:8443/":      PortNotAllowed,
		"https://svc.example.com:0/":         PortNotAllowed,
		"https://b\xc3\xbccher.example.com/": HostNotAName,
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			// A URL the parser refuses never reaches the dialer.
			continue
		}
		req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
		_, err = c.Do(context.Background(), Request{HTTP: req})
		refused(t, err, want)
	}
	if n := res.total(); n != 0 {
		t.Fatalf("%d names were resolved", n)
	}
	// A URL that does not parse is refused by a fetch too, naming nothing.
	_, err := c.Fetch(context.Background(), "https://svc.example.com/%zz", nil)
	refused(t, err, SchemeNotHTTPS)
	if _, err := c.Do(context.Background(), Request{}); err == nil {
		t.Error("a request with no URL was sent")
	}
}

// A port other than 443 is refused unless the catalog entry names it, and
// always for a connector a person added, which names none.
func TestPorts(t *testing.T) {
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res})

	_, err := get(t, c, "https://svc.example.com:8443/", Request{})
	refused(t, err, PortNotAllowed)
	if res.total() != 0 {
		t.Fatal("a refused port resolved its name")
	}
	// The entry names the port: the rule passes, and the address rule is
	// the next to answer.
	_, err = get(t, c, "https://svc.example.com:8443/", Request{Ports: []int{8443}})
	refused(t, err, AddressNotPublic)
	// 443, said or not, passes the port rule.
	for _, raw := range []string{"https://svc.example.com/", "https://svc.example.com:443/"} {
		_, err = get(t, c, raw, Request{})
		refused(t, err, AddressNotPublic)
	}
	if res.count("svc.example.com") != 3 {
		t.Fatalf("resolved %d times", res.count("svc.example.com"))
	}

	// A redirect to a port the entry does not name is refused before it
	// is followed.
	ca := newAuthority(t)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://svc.example.com:8443/next", http.StatusFound)
	}))
	strict := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	_, err = strict.Fetch(context.Background(), srv.url("svc.example.com", "/"), nil)
	refused(t, err, AddressNotPublic) // under a Permit the port is the Permit's, at connect

	// With the switch every port is allowed, and everything else stays.
	open := New(Options{AllowPrivate: true, Resolver: res, Roots: ca.pool})
	if !open.AllowsPrivate() || c.AllowsPrivate() {
		t.Fatal("AllowsPrivate does not say what the client was built with")
	}
	resp, err := get(t, open, srv.url("svc.example.com", "/"), Request{Redirects: 0})
	if resp != nil {
		t.Fatal("a redirect was answered as a response")
	}
	refused(t, err, RedirectRefused)
}

// A name with one address that is not public is refused whole, before any
// connection is opened.
func TestAnyPrivateAnswerRefusesTheName(t *testing.T) {
	ca := newAuthority(t)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1", "10.0.0.7"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	_, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
	refused(t, err, AddressNotPublic)
	if n := srv.conns.Load(); n != 0 {
		t.Fatalf("%d connections were opened", n)
	}
	// The default judgment: one public and one private answer.
	res.set("mixed.example.com", addrs("8.8.8.8", "169.254.169.254"))
	_, err = get(t, New(Options{Resolver: res}), "https://mixed.example.com/", Request{})
	refused(t, err, AddressNotPublic)
	// No answer, and an empty answer, are a failure.
	_, err = get(t, c, "https://nothing.example.com/", Request{})
	refused(t, err, ResolveFailed)
	res.set("empty.example.com", nil)
	res.answers["empty.example.com"] = [][]netip.Addr{{}}
	_, err = get(t, c, "https://empty.example.com/", Request{})
	refused(t, err, ResolveFailed)
	if name, failure, _ := ReasonOf(err); name != ResolveFailed || !failure {
		t.Fatal("a failure to resolve is not retryable")
	}
}

// A name that answers differently a second time is asked once per
// connection, and the socket reaches the address that was checked.
func TestConnectsToTheAddressItChecked(t *testing.T) {
	ca := newAuthority(t)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	res := newResolver()
	// The first answer is the listener; every later one is private.
	res.set("svc.example.com", addrs("127.0.0.1"), addrs("10.0.0.9"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	for range 3 {
		resp, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
		if err == nil {
			_, err = io.ReadAll(resp.Body)
		}
		ok(t, resp, err)
	}
	if res.count("svc.example.com") != 1 || srv.conns.Load() != 1 {
		t.Fatalf("a kept connection resolved %d times over %d connections", res.count("svc.example.com"), srv.conns.Load())
	}
	// A new connection resolves and checks again, and the second answer is
	// refused: nothing reaches the address it named.
	c.CloseIdleConnections()
	_, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
	refused(t, err, AddressNotPublic)
	if res.count("svc.example.com") != 2 || srv.conns.Load() != 1 {
		t.Fatal("a new connection did not resolve and check anew")
	}

	// The socket's control hook applies the same judgment to the literal
	// address about to be connected.
	if err := c.control("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.port)), nil); err != nil {
		t.Fatalf("the hook refused the checked listener: %v", err)
	}
	for _, a := range []string{"10.0.0.9:443", "127.0.0.1:1", "not an address"} {
		refused(t, c.control("tcp", a, nil), AddressNotPublic)
	}
	if err := New(Options{}).control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("the hook refused a public address: %v", err)
	}
}

// A certificate for another name, an expired one and one from an unknown
// authority are refused.
func TestCertificateIsVerifiedForTheName(t *testing.T) {
	ca := newAuthority(t)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cases := map[string]tls.Certificate{
		"another name": ca.leaf(t, []string{"other.example.com"}, nil, time.Now().Add(time.Hour)),
		"expired":      ca.leaf(t, []string{"svc.example.com"}, nil, time.Now().Add(-time.Hour)),
		"unknown":      newAuthority(t).leaf(t, []string{"svc.example.com"}, nil, time.Now().Add(time.Hour)),
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			srv := startServerWith(t, cert, handler)
			res := newResolver()
			res.set("svc.example.com", addrs("127.0.0.1"))
			c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
			_, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
			refused(t, err, CertificateNotVerified)
		})
	}
	// The right name from a known authority is served.
	srv := startServer(t, ca, []string{"svc.example.com"}, handler)
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	resp, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
	ok(t, resp, err)
}

// A discovery fetch follows 3 hops and not a fourth, and refuses a hop to
// http or to a private address; a request that follows none is refused at
// the first 3xx and nothing is sent to its target.
func TestRedirects(t *testing.T) {
	ca := newAuthority(t)
	var mu sync.Mutex
	var seen []string
	var srv *server
	srv = startServer(t, ca, []string{"svc.example.com", "inside.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/hop/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
			if n == 0 {
				_, _ = w.Write([]byte(`{"issuer":"x"}`))
				return
			}
			http.Redirect(w, r, "/hop/"+strconv.Itoa(n-1), http.StatusFound)
		case r.URL.Path == "/plain":
			http.Redirect(w, r, "http://svc.example.com/target", http.StatusMovedPermanently)
		case r.URL.Path == "/inside":
			http.Redirect(w, r, srv.url("inside.example.com", "/target"), http.StatusTemporaryRedirect)
		case r.URL.Path == "/not-modified":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	res.set("inside.example.com", addrs("10.1.2.3"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	ctx := context.Background()

	answer, err := c.Fetch(ctx, srv.url("svc.example.com", "/hop/3"), nil)
	if err != nil || answer.Status != http.StatusOK || !strings.Contains(string(answer.Body), "issuer") {
		t.Fatalf("three hops: %v %+v", err, answer)
	}
	_, err = c.Fetch(ctx, srv.url("svc.example.com", "/hop/4"), nil)
	refused(t, err, TooManyRedirects)
	_, err = c.Fetch(ctx, srv.url("svc.example.com", "/plain"), nil)
	refused(t, err, SchemeNotHTTPS)
	_, err = c.Fetch(ctx, srv.url("svc.example.com", "/inside"), nil)
	refused(t, err, AddressNotPublic)

	mu.Lock()
	seen = nil
	mu.Unlock()
	// A request that follows none: the carrier's, and every one that
	// carries a secret, whatever it asks.
	_, err = get(t, c, srv.url("svc.example.com", "/hop/1"), Request{})
	refused(t, err, RedirectRefused)
	secret := Secret{Value: "s3cret-value", Header: "Authorization", Format: "Bearer {value}", Hosts: catalog.Matcher([]string{"svc.example.com"})}
	_, err = get(t, c, srv.url("svc.example.com", "/hop/1"), Request{Redirects: 3, Secrets: []Secret{secret}})
	refused(t, err, RedirectRefused)
	_, err = get(t, c, srv.url("svc.example.com", "/not-modified"), Request{})
	refused(t, err, RedirectRefused)
	mu.Lock()
	targeted := false
	for _, p := range seen {
		targeted = targeted || p == "/hop/0"
	}
	mu.Unlock()
	if targeted {
		t.Fatal("a redirect's target was requested")
	}
	// A fetch that ends on a 3xx with no target answers it.
	answer, err = c.Fetch(ctx, srv.url("svc.example.com", "/not-modified"), nil)
	if err != nil || answer.Status != http.StatusNotModified {
		t.Fatalf("a 304 at the end of a fetch: %v %d", err, answer.Status)
	}
}

// A secret is written only into an https request whose host matches its
// binding, a request to any other host is not sent, and a caller's own Host
// is replaced.
func TestSecretIsBoundToItsHosts(t *testing.T) {
	ca := newAuthority(t)
	type seen struct {
		host, auth, key, form string
	}
	got := make(chan seen, 8)
	srv := startServer(t, ca, []string{"svc.example.com", "a.b.example.com", "example.com", "other.example.net"},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			got <- seen{host: r.Host, auth: r.Header.Get("Authorization"), key: r.Header.Get("X-Api-Key"), form: string(body)}
		}))
	res := newResolver()
	for _, n := range []string{"svc.example.com", "a.b.example.com", "example.com", "other.example.net"} {
		res.set(n, addrs("127.0.0.1"))
	}
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	wildcard := catalog.Matcher([]string{"*.example.com"})
	bearer := Secret{Value: "token-value-1", Header: "Authorization", Format: "Bearer {value}", Hosts: wildcard}

	for _, name := range []string{"svc.example.com", "a.b.example.com"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.url(name, "/"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "evil.example.net"
		req.Header.Set("Authorization", "Bearer the-callers-own")
		resp, err := c.Do(context.Background(), Request{HTTP: req, Secrets: []Secret{bearer}})
		ok(t, resp, err)
		s := <-got
		if s.auth != "Bearer token-value-1" {
			t.Errorf("%s: the secret was not written in its place: %q", name, s.auth)
		}
		if s.host != net.JoinHostPort(name, strconv.Itoa(srv.port)) {
			t.Errorf("%s: the caller's Host reached the server: %q", name, s.host)
		}
	}
	// The wildcard does not match the bare name, and another domain is not
	// bound: neither request is sent.
	for _, name := range []string{"example.com", "other.example.net"} {
		_, err := get(t, c, srv.url(name, "/"), Request{Secrets: []Secret{bearer}})
		refused(t, err, HostNotBound)
	}
	// The zero matcher binds nothing.
	_, err := get(t, c, srv.url("svc.example.com", "/"), Request{Secrets: []Secret{{Value: "v", Header: "X-Api-Key"}}})
	refused(t, err, HostNotBound)
	select {
	case s := <-got:
		t.Fatalf("a request that was not bound was sent: %+v", s)
	default:
	}

	// A key in a header of the connector's own, with an empty format.
	exact := catalog.Matcher([]string{"svc.example.com"})
	resp, err := get(t, c, srv.url("svc.example.com", "/"), Request{Secrets: []Secret{{Value: "key-value-22", Header: "X-Api-Key", Hosts: exact}}})
	ok(t, resp, err)
	if s := <-got; s.key != "key-value-22" {
		t.Errorf("the key was not placed: %q", s.key)
	}

	// Form members: a refresh token added to a form the caller wrote.
	form := strings.NewReader("grant_type=refresh_token&client_id=pons")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.url("svc.example.com", "/token"), form)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = c.Do(context.Background(), Request{HTTP: req, Secrets: []Secret{
		{Value: "refresh-value-3", FormField: "refresh_token", Hosts: exact},
		{Value: "basic-value-4", Header: "Authorization", Format: "Basic {value}", Hosts: exact},
	}})
	ok(t, resp, err)
	s := <-got
	values, err := url.ParseQuery(s.form)
	if err != nil || values.Get("refresh_token") != "refresh-value-3" || values.Get("grant_type") != "refresh_token" || s.auth != "Basic basic-value-4" {
		t.Errorf("the form was not written: %q %q", s.form, s.auth)
	}
	// A form member into a request with no body.
	resp, err = get(t, c, srv.url("svc.example.com", "/"), Request{Secrets: []Secret{{Value: "only-value-5", FormField: "token", Hosts: exact}}})
	ok(t, resp, err)
	if s := <-got; s.form != "token=only-value-5" {
		t.Errorf("a form member into an empty body: %q", s.form)
	}

	// A secret that names neither place or both, a format without its
	// value or with it twice, and a body that is not a form are refused.
	bad := []Secret{
		{Value: "v", Hosts: exact},
		{Value: "v", Header: "X", FormField: "y", Hosts: exact},
		{Value: "v", Header: "X", Format: "Bearer", Hosts: exact},
		{Value: "v", Header: "X", Format: "{value}{value}", Hosts: exact},
	}
	for _, sec := range bad {
		if _, err := get(t, c, srv.url("svc.example.com", "/"), Request{Secrets: []Secret{sec}}); err == nil {
			t.Errorf("the secret %+v was sent", sec)
		}
	}
	for _, body := range []io.Reader{strings.NewReader("%zz"), strings.NewReader(strings.Repeat("a", maxFetchBody+1)), failingReader{}} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.url("svc.example.com", "/"), body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Do(context.Background(), Request{HTTP: req, Secrets: []Secret{{Value: "v", FormField: "f", Hosts: exact}}}); err == nil {
			t.Error("a body that is not a form was sent with a form member")
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the body fails") }

// The outside client stores no cookie and sends no trace header.
func TestNoCookieAndNoTraceHeaderLeave(t *testing.T) {
	ca := newAuthority(t)
	type seen struct{ cookie, trace, state, baggage, ua string }
	got := make(chan seen, 4)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Header.Get("Cookie"), r.Header.Get("Traceparent"), r.Header.Get("Tracestate"), r.Header.Get("Baggage"), r.UserAgent()}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "kept-by-nobody"})
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	if _, isTransport := any(c.transport).(*http.Transport); !isTransport {
		t.Fatal("the transport is wrapped")
	}
	for range 2 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.url("svc.example.com", "/"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		req.Header.Set("Tracestate", "vendor=1")
		req.Header.Set("Baggage", "user=1")
		_, err = c.Do(context.Background(), Request{HTTP: req})
		refused(t, err, RedirectRefused)
		s := <-got
		if s.cookie != "" || s.trace != "" || s.state != "" || s.baggage != "" {
			t.Fatalf("a cookie or a trace header left: %+v", s)
		}
		if !strings.HasPrefix(s.ua, "pons/") {
			t.Errorf("the user agent is %q", s.ua)
		}
	}
	// A fetch that follows redirects drops the trace headers on every hop
	// and sends no cookie the first hop set.
	_, err := c.Fetch(context.Background(), srv.url("svc.example.com", "/"), nil)
	refused(t, err, TooManyRedirects)
	for len(got) > 0 {
		if s := <-got; s.cookie != "" || s.trace != "" {
			t.Fatalf("a hop carried a cookie or a trace: %+v", s)
		}
	}
}

// Headers over 64 KiB, a fetch's body over 1 MiB after decoding, a connect
// past its bound and a metadata fetch past its bound each end with their
// reason.
func TestLimits(t *testing.T) {
	ca := newAuthority(t)
	big := strings.Repeat("x", maxFetchBody+1)
	exact := strings.Repeat("y", maxFetchBody)
	compressed := func(enc string, n int) []byte {
		var b bytes.Buffer
		var w io.WriteCloser
		if enc == "gzip" {
			w = gzip.NewWriter(&b)
		} else {
			w = zlib.NewWriter(&b)
		}
		_, _ = w.Write(bytes.Repeat([]byte("z"), n))
		_ = w.Close()
		return b.Bytes()
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/headers":
			w.Header().Set("X-Big", strings.Repeat("h", maxHeaderBytes+1))
		case "/big":
			_, _ = w.Write([]byte(big))
		case "/exact":
			_, _ = w.Write([]byte(exact))
		case "/gzip", "/deflate":
			enc := strings.TrimPrefix(r.URL.Path, "/")
			w.Header().Set("Content-Encoding", enc)
			_, _ = w.Write(compressed(enc, maxFetchBody+1))
		case "/gzip-small":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressed("gzip", 10))
		case "/bad-gzip":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("not gzip"))
		case "/slow":
			select {
			case <-release:
			case <-r.Context().Done():
			}
		case "/slow-body":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	ctx := context.Background()

	_, err := get(t, c, srv.url("svc.example.com", "/headers"), Request{})
	refused(t, err, ResponseTooLarge)
	for _, path := range []string{"/big", "/gzip", "/deflate"} {
		_, err = c.Fetch(ctx, srv.url("svc.example.com", path), nil)
		refused(t, err, ResponseTooLarge)
	}
	if a, err := c.Fetch(ctx, srv.url("svc.example.com", "/exact"), nil); err != nil || len(a.Body) != maxFetchBody {
		t.Fatalf("a body at its bound: %v %d", err, len(a.Body))
	}
	if a, err := c.Fetch(ctx, srv.url("svc.example.com", "/gzip-small"), nil); err != nil || string(a.Body) != strings.Repeat("z", 10) {
		t.Fatalf("a small gzip body: %v %q", err, a.Body)
	}
	// A coding the transport left in place, because the caller asked for
	// it, is undone by the dialer and bounded after.
	for _, path := range []string{"/gzip", "/deflate"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.url("svc.example.com", path), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept-Encoding", strings.TrimPrefix(path, "/"))
		resp, err := c.Do(ctx, Request{HTTP: req, MaxBody: maxFetchBody})
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(resp.Body)
		refused(t, err, ResponseTooLarge)
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.url("svc.example.com", "/bad-gzip"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.Do(ctx, Request{HTTP: req, MaxBody: 100})
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	refused(t, err, ConnectFailed)
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	// The bounds are the package's constants, shortened here so the test
	// does not wait them out.
	if connectTimeout != 10*time.Second || fetchTimeout != 15*time.Second || secretTimeout != 15*time.Second ||
		maxHeaderBytes != 64<<10 || maxFetchBody != 1<<20 {
		t.Fatal("a limit is not the spec's")
	}
	short := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	short.connectTimeout, short.fetchTimeout, short.secretTimeout = 200*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond

	// A metadata fetch past its bound.
	_, err = short.Fetch(ctx, srv.url("svc.example.com", "/slow"), nil)
	refused(t, err, Timeout)
	// A request that carries a secret, past its bound.
	_, err = get(t, short, srv.url("svc.example.com", "/slow"), Request{Timeout: time.Hour, Secrets: []Secret{
		{Value: "v-secret", Header: "Authorization", Hosts: catalog.Matcher([]string{"svc.example.com"})},
	}})
	refused(t, err, Timeout)
	// The wait for headers.
	_, err = get(t, c, srv.url("svc.example.com", "/slow"), Request{HeaderTimeout: 100 * time.Millisecond})
	refused(t, err, Timeout)
	// A body read past the request's bound.
	resp, err = get(t, c, srv.url("svc.example.com", "/slow-body"), Request{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	refused(t, err, Timeout)
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	// Resolving past the connect bound.
	blocked := newResolver()
	blocked.block = true
	slow := New(Options{Resolver: blocked, Roots: ca.pool, Permit: listeners(srv.port)})
	slow.connectTimeout = 100 * time.Millisecond
	_, err = get(t, slow, srv.url("svc.example.com", "/"), Request{})
	refused(t, err, Timeout)

	// A handshake past the connect bound: a listener that never answers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	silentPort := ln.Addr().(*net.TCPAddr).Port
	silent := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(silentPort)})
	silent.connectTimeout = 100 * time.Millisecond
	_, err = get(t, silent, "https://svc.example.com:"+strconv.Itoa(silentPort)+"/", Request{})
	refused(t, err, Timeout)

	// A connection nobody accepts is a failure, not a rule.
	closedPort := freePort(t)
	refusing := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(closedPort)})
	_, err = get(t, refusing, "https://svc.example.com:"+strconv.Itoa(closedPort)+"/", Request{})
	refused(t, err, ConnectFailed)
}

// freePort is a loopback port nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// A proxy variable of the environment is ignored.
func TestNoProxyFromTheEnvironment(t *testing.T) {
	ca := newAuthority(t)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unused := freePort(t)
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		t.Setenv(v, "http://127.0.0.1:"+strconv.Itoa(unused))
	}
	t.Setenv("NO_PROXY", "")
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	resp, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
	ok(t, resp, err)
	if srv.conns.Load() != 1 {
		t.Fatal("the request did not go directly")
	}
	// The operator client ignores them too.
	cert := ca.leaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(time.Hour))
	opSrv := startServerWith(t, cert, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	op := Operator(OperatorOptions{Roots: ca.pool})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, opSrv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	opResp, err := op.Do(req)
	ok(t, opResp, err)
}

// proxy is a CONNECT proxy a test runs, which records each CONNECT.
type proxy struct {
	addr     string
	mu       sync.Mutex
	connects []string
	auth     []string
	answer   int
}

func startProxy(t *testing.T, cert *tls.Certificate) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cert != nil {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
	}
	p := &proxy{addr: ln.Addr().String(), answer: http.StatusOK}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *proxy) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, req.RequestURI)
	p.auth = append(p.auth, req.Header.Get("Proxy-Authorization"))
	answer := p.answer
	p.mu.Unlock()
	if answer != http.StatusOK {
		_, _ = io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(answer)+" no\r\nContent-Length: 0\r\n\r\n")
		return
	}
	target, err := net.Dial("tcp", req.RequestURI)
	if err != nil {
		return
	}
	defer func() { _ = target.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

func (p *proxy) seen() (connects, auth []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...), append([]string(nil), p.auth...)
}

// With a proxy every outside request leaves through it, its CONNECT names
// the checked address and never the name, and a name with a private address
// is never handed to it.
func TestOutboundProxy(t *testing.T) {
	ca := newAuthority(t)
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Host))
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	res.set("inside.example.com", addrs("10.0.0.1"))

	p := startProxy(t, nil)
	proxyURL := &url.URL{Scheme: "http", Host: p.addr, User: url.UserPassword("operator", "proxy-password")}
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port), Proxy: proxyURL})
	resp, err := get(t, c, srv.url("svc.example.com", "/"), Request{})
	if err != nil {
		t.Fatal(err)
	}
	host, err := io.ReadAll(resp.Body)
	ok(t, resp, err)
	connects, auth := p.seen()
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.port))
	if len(connects) != 1 || connects[0] != want {
		t.Fatalf("the CONNECTs were %v, want %s", connects, want)
	}
	if string(host) != net.JoinHostPort("svc.example.com", strconv.Itoa(srv.port)) {
		t.Fatalf("the name did not travel inside the tunnel: %q", host)
	}
	if auth[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("operator:proxy-password")) {
		t.Fatalf("the proxy's credential was %q", auth[0])
	}
	if srv.conns.Load() != 1 {
		t.Fatal("the server was not reached through the tunnel")
	}

	// A name with a private address is never handed to the proxy.
	_, err = get(t, c, "https://inside.example.com:"+strconv.Itoa(srv.port)+"/", Request{})
	refused(t, err, AddressNotPublic)
	if connects, _ := p.seen(); len(connects) != 1 {
		t.Fatalf("the proxy was handed a refused name: %v", connects)
	}

	// A proxy that refuses the tunnel is a failure.
	p.mu.Lock()
	p.answer = http.StatusForbidden
	p.mu.Unlock()
	c.CloseIdleConnections()
	_, err = get(t, c, srv.url("svc.example.com", "/"), Request{})
	refused(t, err, ConnectFailed)

	// A proxy over https, with no port named, and no credential.
	cert := ca.leaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(time.Hour))
	tp := startProxy(t, &cert)
	tc := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port), Proxy: &url.URL{Scheme: "https", Host: tp.addr}})
	resp, err = get(t, tc, srv.url("svc.example.com", "/"), Request{})
	ok(t, resp, err)
	if connects, auth := tp.seen(); len(connects) != 1 || auth[0] != "" {
		t.Fatalf("the https proxy saw %v %v", connects, auth)
	}
	// A proxy over https whose certificate does not verify.
	untrusted := New(Options{Resolver: res, Roots: newAuthority(t).pool, Permit: listeners(srv.port), Proxy: &url.URL{Scheme: "https", Host: tp.addr}})
	_, err = get(t, untrusted, srv.url("svc.example.com", "/"), Request{})
	refused(t, err, ConnectFailed)
	// A proxy nobody answers at, and a proxy named without a port: the
	// default ports of each scheme, where nothing listens on a test host.
	for _, u := range []*url.URL{
		{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))},
		{Scheme: "http", Host: "127.0.0.1"},
		{Scheme: "https", Host: "127.0.0.1"},
	} {
		dead := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port), Proxy: u})
		_, err = get(t, dead, srv.url("svc.example.com", "/"), Request{})
		if name, _, _ := ReasonOf(err); name != ConnectFailed && name != Timeout {
			t.Fatalf("a dead proxy %s: %v", u.Scheme, err)
		}
	}
}

// The operator client verifies against its roots with TLS 1.2 or later and
// is bounded by its timeout.
func TestOperatorClient(t *testing.T) {
	ca := newAuthority(t)
	cert := ca.leaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(time.Hour))
	srv := startServerWith(t, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	op := Operator(OperatorOptions{Roots: ca.pool, Timeout: 5 * time.Second})
	if op.Timeout != 5*time.Second {
		t.Fatal("the timeout was not kept")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := op.Do(req)
	ok(t, resp, err)
	// Another authority is refused.
	other := Operator(OperatorOptions{Roots: newAuthority(t).pool})
	if resp, err := other.Do(req); err == nil {
		ok(t, resp, err)
		t.Fatal("a certificate of an unknown authority was accepted")
	}
}

// A refusal names its rule and never an address; a caller that went away
// is told so.
func TestRefusalText(t *testing.T) {
	for name := range map[string]bool{SchemeNotHTTPS: false, Timeout: true} {
		r := refuse(name)
		if r.Error() != "dial: "+name {
			t.Errorf("the text of %s is %q", name, r.Error())
		}
		if _, failure, _ := ReasonOf(r); failure != failures[name] {
			t.Errorf("%s: failure %v", name, failure)
		}
	}
	if _, _, ok := ReasonOf(errors.New("other")); ok {
		t.Error("ReasonOf read a refusal from an error that holds none")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := classify(canceled, errors.New("x")); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled caller: %v", err)
	}
	if err := classify(context.Background(), &net.OpError{Op: "dial", Err: errors.New("dial tcp 10.0.0.1:443")}); err.Error() != "dial: connect_failed" {
		t.Errorf("an address reached a refusal's text: %v", err)
	}

	// A caller that goes away during a request.
	ca := newAuthority(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	ctx, stop := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.url("svc.example.com", "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(50*time.Millisecond, stop)
	if _, err := c.Do(ctx, Request{HTTP: req}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a caller that went away: %v", err)
	}
	// The plain dial is refused.
	if _, err := refusePlain(context.Background(), "tcp", "svc.example.com:80"); err == nil {
		t.Fatal("a plain connection was opened")
	}
	// A transport address the dialer cannot read.
	for _, hp := range []string{"no-port", "svc.example.com:x", "svc.example.com:0", "localhost:443"} {
		if _, err := c.dialTLS(context.Background(), "tcp", hp); err == nil {
			t.Errorf("dialTLS(%q) connected", hp)
		}
	}
}

// A forwarded call carries its secret past the sign-in's bound, its time is
// the carrier's, and a 3xx comes back as it came, followed nowhere.
func TestAForwardedCallIsTheCarriers(t *testing.T) {
	ca := newAuthority(t)
	var mu sync.Mutex
	var seen []string
	srv := startServer(t, ca, []string{"svc.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		switch r.URL.Path {
		case "/slow":
			time.Sleep(400 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		case "/moved":
			http.Redirect(w, r, "https://elsewhere.example.com/target", http.StatusFound)
		}
	}))
	res := newResolver()
	res.set("svc.example.com", addrs("127.0.0.1"))
	c := New(Options{Resolver: res, Roots: ca.pool, Permit: listeners(srv.port)})
	c.secretTimeout = 100 * time.Millisecond
	secret := []Secret{{Value: "Bearer forwarded-secret", Header: "Authorization", Hosts: catalog.Matcher([]string{"svc.example.com"})}}

	_, err := get(t, c, srv.url("svc.example.com", "/slow"), Request{Secrets: secret})
	refused(t, err, Timeout)
	resp, err := get(t, c, srv.url("svc.example.com", "/slow"), Request{Secrets: secret, Forward: true})
	ok(t, resp, err)
	resp, err = get(t, c, srv.url("svc.example.com", "/moved"), Request{Secrets: secret, Forward: true})
	if err != nil || resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://elsewhere.example.com/target" {
		t.Fatalf("a forwarded 3xx: %v", err)
	}
	ok(t, resp, err)
	if _, err := get(t, c, srv.url("svc.example.com", "/moved"), Request{Secrets: secret}); err == nil {
		t.Fatal("a 3xx to a request that is no forwarded call is answered")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if strings.Contains(s, "target") {
			t.Fatalf("a redirect was followed: %v", seen)
		}
	}
}

// A read the request's bound ended is a timeout, and one its caller ended is
// a cancel, even when the transport reports the cancelled read as the end of
// the body; a body read to its end before either is whole.
func TestAReadEndedByItsBoundIsATimeoutHoweverItEnds(t *testing.T) {
	expired, stop := context.WithTimeout(context.Background(), time.Nanosecond)
	defer stop()
	<-expired.Done()
	body := &classified{rc: io.NopCloser(strings.NewReader("")), caller: context.Background(), req: expired}
	_, err := io.ReadAll(body)
	refused(t, err, Timeout)

	caller, leave := context.WithCancel(context.Background())
	leave()
	body = &classified{rc: io.NopCloser(strings.NewReader("")), caller: caller, req: caller}
	if _, err := io.ReadAll(body); !errors.Is(err, context.Canceled) {
		t.Fatalf("a read its caller ended: %v, want context.Canceled", err)
	}

	body = &classified{rc: io.NopCloser(strings.NewReader("whole")), caller: context.Background(), req: context.Background()}
	if got, err := io.ReadAll(body); err != nil || string(got) != "whole" {
		t.Fatalf("a body read to its end: %q, %v", got, err)
	}
}
