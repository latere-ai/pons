// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"latere.ai/x/pkg/hostmatch"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/version"
)

// Resolver resolves a name to its addresses. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures the outside client. None of them is set by a variable
// but AllowPrivate and Proxy.
type Options struct {
	// AllowPrivate treats every address as public and allows every port,
	// for a server run against stubs on loopback
	// (PONS_DIAL_ALLOW_PRIVATE). Everything else stays: https, the
	// certificate, the host rule, redirects, bindings and limits.
	AllowPrivate bool
	// Proxy, when set, is the operator's proxy every request leaves
	// through, as a tunnel to the checked address (PONS_OUTBOUND_PROXY).
	Proxy *url.URL
	// Permit, when set, judges an address and a port in place of Public
	// and the port rule: a test permits the stubs' listeners alone.
	// AllowPrivate is a Permit that admits everything.
	Permit func(addr netip.Addr, port int) bool
	// Resolver resolves names. Nil is the process's resolver.
	Resolver Resolver
	// Roots are the authorities a certificate is verified against. Nil is
	// the process's roots.
	Roots *x509.CertPool
}

// Client is the outside client. It keeps no cookie, sends no trace header,
// reads no proxy from the environment and caches no answer of a resolver.
type Client struct {
	permit    func(netip.Addr, int) bool
	resolver  Resolver
	roots     *x509.CertPool
	proxy     *url.URL
	transport *http.Transport

	// The limits, copied from the constants so a test can shorten them.
	connectTimeout time.Duration
	fetchTimeout   time.Duration
	secretTimeout  time.Duration
	maxFetchBody   int64
}

// New builds the outside client. It sends nothing.
func New(o Options) *Client {
	c := &Client{
		permit: o.Permit, resolver: o.Resolver, roots: o.Roots, proxy: o.Proxy,
		connectTimeout: connectTimeout, fetchTimeout: fetchTimeout,
		secretTimeout: secretTimeout, maxFetchBody: maxFetchBody,
	}
	if o.AllowPrivate {
		c.permit = func(netip.Addr, int) bool { return true }
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}
	c.transport = &http.Transport{
		// No proxy from the environment: PONS_OUTBOUND_PROXY is the only
		// one, and it is dialed by dialTLS.
		Proxy:                  nil,
		DialContext:            refusePlain,
		DialTLSContext:         c.dialTLS,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           64,
		MaxIdleConnsPerHost:    16,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
	return c
}

// AllowsPrivate reports whether the client treats every address as public,
// for the start's warning, ponsd check and /readyz.
func (c *Client) AllowsPrivate() bool { return c.permit != nil }

// CloseIdleConnections closes the connections kept for reuse, so the next
// request opens, resolves and checks anew.
func (c *Client) CloseIdleConnections() { c.transport.CloseIdleConnections() }

// refusePlain is the transport's dial for a URL that is not https. The
// checks refuse one before a request is sent, so this is reached by no
// path; it stays closed in case one is ever added.
func refusePlain(context.Context, string, string) (net.Conn, error) {
	return nil, refuse(SchemeNotHTTPS)
}

// Secret is a value the dialer writes into a request as its last step
// before the request is sent, and only when the request is https, its host
// matches Hosts and its port passed the port rule. A caller of the dialer
// never writes a secret into a request itself.
type Secret struct {
	// Value is the secret.
	Value string
	// Header is the request header the value is placed in, valued by
	// Format with the value in place of "{value}", which appears exactly
	// once. An empty Format is "{value}".
	Header string
	Format string
	// FormField is the member of a form body the value is placed in, in
	// place of a header.
	FormField string
	// Hosts are the hosts the value may be sent to: an exact name, or any
	// name under a "*." pattern at any depth and never the name itself.
	// The zero matcher matches nothing.
	Hosts hostmatch.Matcher
}

// Request is one request of the outside client.
type Request struct {
	// HTTP is the request. Its Host is replaced by the URL's.
	HTTP *http.Request
	// Secrets are written in last, each toward its hosts.
	Secrets []Secret
	// Ports are the ports beside 443 the connector's catalog entry names,
	// for the URL and every redirect. A connector a person added names
	// none.
	Ports []int
	// Redirects is how many redirects are followed: 0 for every request
	// but a discovery fetch, which follows 3 at most. A request that
	// carries a secret follows none, whatever this says.
	Redirects int
	// Timeout bounds the whole request, its body included. Zero is no
	// bound of the dialer's own, but a request that carries a secret is
	// bounded by 15 seconds.
	Timeout time.Duration
	// HeaderTimeout bounds the wait for the response's headers.
	HeaderTimeout time.Duration
	// MaxBody bounds the response's body, counted after a content coding
	// is undone; reading past it fails with response_too_large. Zero
	// streams the body unbounded, for the carrier.
	MaxBody int64
	// Forward marks a call the carrier forwards. Its bounds are the
	// carrier's, HeaderTimeout and the carrier's idle time, not the
	// sign-in's 15 seconds for a request that carries a secret; and a 3xx
	// is answered as it came, followed nowhere, for the carrier to judge.
	Forward bool
}

// headersThatLeaveNot are removed from every request: a trace header, so
// no trace leaves the installation.
var headersThatLeaveNot = []string{"Traceparent", "Tracestate", "Baggage", "X-Trace-Id"}

// Do sends one request. Every error but a canceled caller's is a *Refusal.
// The caller closes the response's body. A 3xx to a request that follows no
// redirect is redirect_refused, and nothing is sent to its target.
func (c *Client) Do(ctx context.Context, r Request) (*http.Response, error) {
	if r.HTTP == nil || r.HTTP.URL == nil {
		return nil, errors.New("dial: the request has no URL")
	}
	u := r.HTTP.URL
	if err := c.checkURL(u, r.Ports); err != nil {
		return nil, err
	}
	redirects := min(max(r.Redirects, 0), maxRedirects)
	timeout := r.Timeout
	if len(r.Secrets) > 0 {
		redirects = 0
		if !r.Forward && (timeout <= 0 || timeout > c.secretTimeout) {
			timeout = c.secretTimeout
		}
	}

	var (
		reqCtx context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		reqCtx, cancel = context.WithCancel(ctx)
	}
	out := r.HTTP.Clone(reqCtx)
	out.Host = u.Host
	out.Header.Del("Host")
	for _, h := range headersThatLeaveNot {
		out.Header.Del(h)
	}
	if out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", version.UserAgent())
	}
	if err := writeSecrets(out, r.Secrets); err != nil {
		cancel()
		return nil, err
	}

	hc := &http.Client{Transport: c.transport, CheckRedirect: c.redirects(redirects, r.Ports)}
	if r.Forward {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	var headerLate atomic.Bool
	var timer *time.Timer
	if r.HeaderTimeout > 0 {
		timer = time.AfterFunc(r.HeaderTimeout, func() { headerLate.Store(true); cancel() })
	}
	resp, err := hc.Do(out)
	if timer != nil {
		timer.Stop()
	}
	if err == nil && headerLate.Load() {
		err = refuse(Timeout)
		closeQuietly(resp.Body)
	}
	if err != nil {
		cancel()
		if headerLate.Load() {
			return nil, refuse(Timeout)
		}
		return nil, classify(ctx, err)
	}
	if redirects == 0 && !r.Forward && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		closeQuietly(resp.Body)
		cancel()
		return nil, refuse(RedirectRefused)
	}
	body := io.ReadCloser(&classified{rc: resp.Body, caller: ctx, req: reqCtx})
	if r.MaxBody > 0 {
		body = bounded(resp, body, r.MaxBody)
	}
	resp.Body = &cancelOnClose{ReadCloser: body, cancel: cancel}
	return resp, nil
}

// Answer is what a fetch read.
type Answer struct {
	Status int
	Header http.Header
	Body   []byte
}

// Fetch is a discovery fetch: a GET that carries nothing, follows at most 3
// redirects, ends within 15 seconds whole, and reads at most 1 MiB of body
// after a content coding is undone. ports are the ports beside 443 the
// connector's catalog entry names.
func (c *Client) Fetch(ctx context.Context, rawURL string, ports []int) (Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		// The parse error quotes the URL, so it is not kept.
		return Answer{}, refuse(SchemeNotHTTPS)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(ctx, Request{HTTP: req, Ports: ports, Redirects: maxRedirects, MaxBody: c.maxFetchBody})
	if err != nil {
		return Answer{}, err
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil && cerr != nil {
		err = classify(ctx, cerr)
	}
	if err != nil {
		return Answer{}, err
	}
	return Answer{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// checkURL is the four checks that need no network: the scheme is https,
// there is no user part, the host passes the host rule, and the port is 443
// or one the catalog entry names. Under a Permit the port is the Permit's
// to judge, when the address is known.
func (c *Client) checkURL(u *url.URL, ports []int) error {
	if u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		// A user part makes an address that is not a plain https address
		// either: the name it reaches is not the name it reads as.
		return refuse(SchemeNotHTTPS)
	}
	if u.Hostname() == "" || catalog.CheckHost(u.Hostname()) != nil {
		return refuse(HostNotAName)
	}
	port, err := portOf(u)
	if err != nil {
		return refuse(PortNotAllowed)
	}
	if c.permit == nil && port != 443 && !slices.Contains(ports, port) {
		return refuse(PortNotAllowed)
	}
	return nil
}

// portOf is the port of an https URL, 443 when it names none.
func portOf(u *url.URL) (int, error) {
	p := u.Port()
	if p == "" {
		return 443, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, refuse(PortNotAllowed)
	}
	return n, nil
}

// redirects is the redirect rule of one request: at most limit hops, each
// held to the four checks; the transport then resolves and checks the
// hop's address anew.
func (c *Client) redirects(limit int, ports []int) func(*http.Request, []*http.Request) error {
	return func(next *http.Request, via []*http.Request) error {
		if limit == 0 {
			return refuse(RedirectRefused)
		}
		if len(via) > limit {
			return refuse(TooManyRedirects)
		}
		if err := c.checkURL(next.URL, ports); err != nil {
			return err
		}
		next.Host = next.URL.Host
		for _, h := range headersThatLeaveNot {
			next.Header.Del(h)
		}
		return nil
	}
}

// writeSecrets writes every secret into the request, the dialer's last step,
// or refuses the request whole with host_not_bound when one is not bound to
// its host.
func writeSecrets(req *http.Request, secrets []Secret) error {
	if len(secrets) == 0 {
		return nil
	}
	host := catalog.Normalize(req.URL.Hostname())
	form := url.Values{}
	for _, s := range secrets {
		if req.URL.Scheme != "https" || !s.Hosts.Matches(host) {
			return refuse(HostNotBound)
		}
		switch {
		case s.Header != "" && s.FormField == "":
			format := s.Format
			if format == "" {
				format = "{value}"
			}
			if strings.Count(format, "{value}") != 1 {
				return errors.New("dial: a secret's format holds {value} other than once")
			}
			req.Header.Set(s.Header, strings.Replace(format, "{value}", s.Value, 1))
		case s.FormField != "" && s.Header == "":
			form.Set(s.FormField, s.Value)
		default:
			return errors.New("dial: a secret names a header or a form field, one of the two")
		}
	}
	if len(form) == 0 {
		return nil
	}
	return writeForm(req, form)
}

// writeForm adds the members to the request's form body.
func writeForm(req *http.Request, add url.Values) error {
	values := url.Values{}
	if req.Body != nil && req.Body != http.NoBody {
		raw, err := io.ReadAll(io.LimitReader(req.Body, maxFetchBody+1))
		if cerr := req.Body.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return errors.New("dial: the form body cannot be read")
		}
		if len(raw) > maxFetchBody {
			return errors.New("dial: the form body is over its bound")
		}
		if values, err = url.ParseQuery(string(raw)); err != nil {
			return errors.New("dial: the body is not a form")
		}
	}
	maps.Copy(values, add)
	encoded := []byte(values.Encode())
	req.Body = io.NopCloser(bytes.NewReader(encoded))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(encoded)), nil }
	req.ContentLength = int64(len(encoded))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return nil
}

// bounded undoes a content coding the transport left in place and bounds
// what is read after it.
func bounded(resp *http.Response, body io.ReadCloser, limit int64) io.ReadCloser {
	var decoded io.Reader = body
	if !resp.Uncompressed {
		switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
		case "gzip", "x-gzip":
			decoded = &lazyDecoder{src: body, open: func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }}
		case "deflate":
			decoded = &lazyDecoder{src: body, open: func(r io.Reader) (io.Reader, error) { return zlib.NewReader(r) }}
		}
	}
	return &limited{r: decoded, closer: body, left: limit}
}

// lazyDecoder opens its decoder on the first read, so a body is not read
// before its reader asks.
type lazyDecoder struct {
	src  io.Reader
	open func(io.Reader) (io.Reader, error)
	once sync.Once
	dec  io.Reader
	err  error
}

func (l *lazyDecoder) Read(p []byte) (int, error) {
	l.once.Do(func() { l.dec, l.err = l.open(l.src) })
	if l.err != nil {
		var r *Refusal
		if errors.As(l.err, &r) {
			return 0, l.err
		}
		return 0, refuse(ConnectFailed)
	}
	n, err := l.dec.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		var r *Refusal
		if !errors.As(err, &r) {
			err = refuse(ConnectFailed)
		}
	}
	return n, err
}

// limited fails with response_too_large past its bound, so a body over its
// bound is never cut short and used.
type limited struct {
	r      io.Reader
	closer io.Closer
	left   int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left < 0 {
		return 0, refuse(ResponseTooLarge)
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return 0, refuse(ResponseTooLarge)
	}
	return n, err
}

func (l *limited) Close() error { return l.closer.Close() }

// classified names a body's read error as a refusal, so the text of a
// transport's error never reaches whoever reads the body.
type classified struct {
	rc     io.ReadCloser
	caller context.Context
	// req is the request's own context, which its bound ends.
	req context.Context
}

// Read names what ended a read. A read that the request's bound or its
// caller cancelled can end as the end of the body; it is that cancellation,
// a timeout or a cancel, and never a body read whole.
func (c *classified) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		if cause := c.req.Err(); cause != nil {
			err = classify(c.caller, cause)
		}
	default:
		err = classify(c.caller, err)
	}
	return n, err
}

func (c *classified) Close() error { return c.rc.Close() }

// cancelOnClose ends the request's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// closeQuietly closes a body the dialer refuses. Nothing of it is read, and
// a failure to close it changes no answer: the request is already refused.
func closeQuietly(rc io.ReadCloser) {
	if rc != nil {
		_ = rc.Close()
	}
}
