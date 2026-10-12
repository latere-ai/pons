// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// authority is a certificate authority a test makes.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dial test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authority{cert: cert, key: key, pool: pool}
}

var serial atomic.Int64

// leaf issues a certificate for the names and addresses, valid until
// notAfter.
func (a *authority) leaf(t *testing.T, names []string, ips []net.IP, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1) + 1),
		Subject:      pkix.Name{CommonName: "dial test"},
		DNSNames:     names,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// server is a TLS server on loopback with a certificate for the names.
type server struct {
	*httptest.Server
	port  int
	conns atomic.Int64
}

func startServer(t *testing.T, ca *authority, names []string, h http.Handler) *server {
	t.Helper()
	return startServerWith(t, ca.leaf(t, names, nil, time.Now().Add(time.Hour)), h)
}

func startServerWith(t *testing.T, cert tls.Certificate, h http.Handler) *server {
	t.Helper()
	s := &server{}
	hs := httptest.NewUnstartedServer(h)
	hs.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	// A handshake a test refuses on purpose is no news.
	hs.Config.ErrorLog = log.New(io.Discard, "", 0)
	hs.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	hs.StartTLS()
	t.Cleanup(hs.Close)
	s.Server = hs
	_, port, err := net.SplitHostPort(hs.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if s.port, err = strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	return s
}

// url is the server's address under a name.
func (s *server) url(name, path string) string {
	return "https://" + net.JoinHostPort(name, strconv.Itoa(s.port)) + path
}

// resolver answers names from a table, one answer per call in turn, the
// last one repeated, and counts the calls.
type resolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
	block   bool
}

func newResolver() *resolver {
	return &resolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

func (r *resolver) set(name string, answers ...[]netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[name] = answers
}

func (r *resolver) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

func (r *resolver) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		n += c
	}
	return n
}

func (r *resolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.calls[host]++
	n := r.calls[host]
	answers, block := r.answers[host], r.block
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if len(answers) == 0 {
		return nil, errors.New("no such host")
	}
	return answers[min(n, len(answers))-1], nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

// listeners is a Permit that admits the loopback address on the listed
// ports alone, so the address check stays on in a test.
func listeners(ports ...int) func(netip.Addr, int) bool {
	return func(a netip.Addr, p int) bool {
		if a.Unmap() != loopback {
			return false
		}
		return slices.Contains(ports, p)
	}
}

// get sends a GET through the client.
func get(t *testing.T, c *Client, rawURL string, r Request) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.HTTP = req
	return c.Do(context.Background(), r)
}

// refused fails unless err is the refusal of the name.
func refused(t *testing.T, err error, name string) {
	t.Helper()
	got, _, ok := ReasonOf(err)
	if !ok || got != name {
		t.Fatalf("want the refusal %s, got %v", name, err)
	}
}

// ok reads and closes a response that must have succeeded.
func ok(t *testing.T, resp *http.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
}
