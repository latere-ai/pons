// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package stubs holds the stub services the tests of Pons run against,
// each started by a test in its own process (specs/011-distribution.md).
// Each listens on loopback over TLS, with a certificate from one authority
// the package makes at start, and each records every request it served.
//
// Two are here: an issuer, which mints tokens for any subject, audience and
// session claim, and an authorizer, which answers the contract of
// specs/004-identity-and-authorization.md from a table and records every
// question. The connector, the authorization server, the API and the git
// host join them with the carrier and the sign-in, each in a file of its
// own beside these, on the same authority.
//
// The package is public, so a consumer's own tests can start the stubs.
package stubs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// authority is the one certificate authority of a process's stubs.
type authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pool *x509.CertPool
}

var (
	authorityOnce sync.Once
	theAuthority  *authority
	authorityErr  error
)

// ca is the process's authority, made on first use.
func ca() (*authority, error) {
	authorityOnce.Do(func() { theAuthority, authorityErr = newAuthority() })
	return theAuthority, authorityErr
}

func newAuthority() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("stubs: the authority's key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Pons stub authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("stubs: the authority's certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("stubs: the authority's certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authority{key: key, cert: cert, pool: pool}, nil
}

// Roots is the pool of the stubs' authority, the roots a server under test
// verifies the stubs against.
func Roots() (*x509.CertPool, error) {
	a, err := ca()
	if err != nil {
		return nil, err
	}
	return a.pool, nil
}

// Certificate is a certificate of the stubs' authority for the names: each
// a DNS name or an IP address.
func Certificate(names ...string) (tls.Certificate, error) {
	a, err := ca()
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stubs: a key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stubs: a serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(23 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stubs: a certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key}, nil
}

// TB is the part of testing.TB the stubs use.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// serveTLS starts h on a loopback listener over TLS with a certificate for
// 127.0.0.1 and the names, and stops it with the test.
func serveTLS(t TB, h http.Handler, names ...string) *httptest.Server {
	t.Helper()
	cert, err := Certificate(append([]string{"127.0.0.1"}, names...)...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// deferred is a handler set after the listener it serves on exists, since a
// stub's handler names its own address.
type deferred struct {
	mu sync.RWMutex
	h  http.Handler
}

func (d *deferred) set(h http.Handler) {
	d.mu.Lock()
	d.h = h
	d.mu.Unlock()
}

func (d *deferred) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	h := d.h
	d.mu.RUnlock()
	h.ServeHTTP(w, r)
}
