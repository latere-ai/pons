// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"latere.ai/x/pkg/otel"
)

// OperatorOptions configures the operator client.
type OperatorOptions struct {
	// Roots are the authorities a certificate is verified against. Nil is
	// the process's roots: a certificate authority of the operator's own
	// is trusted the way the process trusts any. A test passes the stubs'.
	Roots *x509.CertPool
	// Timeout bounds one request, its body included. Zero is no bound of
	// the client's own: the caller bounds the request through its context.
	Timeout time.Duration
}

// Operator builds the operator client of specs/009-outbound-requests.md:
// the client toward the addresses the operator wrote into the
// configuration, the issuers' key sets and the authorizer. No address rule
// applies to it, because the operator named those addresses, and only
// internal/access takes it. It reads no proxy from the environment, verifies
// certificates against Roots with TLS 1.2 or later, and carries the trace
// to the services it reaches.
func Operator(o OperatorOptions) *http.Client {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.Roots},
		TLSHandshakeTimeout:    connectTimeout,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{Transport: otel.Transport(transport), Timeout: o.Timeout}
}
