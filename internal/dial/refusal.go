// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// The names of the refusals and failures of specs/009-outbound-requests.md.
// A name is what a route's details.reason carries and what the refusals are
// counted by.
const (
	SchemeNotHTTPS         = "scheme_not_https"
	HostNotAName           = "host_not_a_name"
	PortNotAllowed         = "port_not_allowed"
	AddressNotPublic       = "address_not_public"
	CertificateNotVerified = "certificate_not_verified"
	RedirectRefused        = "redirect_refused"
	TooManyRedirects       = "too_many_redirects"
	HostNotBound           = "host_not_bound"
	ResponseTooLarge       = "response_too_large"

	ResolveFailed = "resolve_failed"
	ConnectFailed = "connect_failed"
	Timeout       = "timeout"
)

// failures are the names that are a failure, not a rule: the same request
// may succeed later.
var failures = map[string]bool{ResolveFailed: true, ConnectFailed: true, Timeout: true}

// Refusal is every error the outside client returns but a canceled
// caller's. Its text is its name and nothing else: never a resolved
// address, a redirect's target, a query string or any part of an answer,
// so a refusal is no map of the installation's network. It wraps nothing
// for the same reason.
type Refusal struct {
	// Name is one word of the table.
	Name string
}

func (r *Refusal) Error() string { return "dial: " + r.Name }

// Failure reports whether the refusal is a failure rather than a rule, and
// so whether the same request may succeed later.
func (r *Refusal) Failure() bool { return failures[r.Name] }

func refuse(name string) *Refusal { return &Refusal{Name: name} }

// ReasonOf reads the refusal in err: its name, whether it is a failure, and
// ok false when err holds none.
func ReasonOf(err error) (name string, failure, ok bool) {
	var r *Refusal
	if !errors.As(err, &r) {
		return "", false, false
	}
	return r.Name, r.Failure(), true
}

// classify turns what the transport answered into a refusal. A refusal of
// the dialer's own comes back as it was; a caller that went away is
// context.Canceled; everything else is named by what failed, and the text
// of the transport's error, which can carry the whole URL, is dropped.
func classify(caller context.Context, err error) error {
	var r *Refusal
	if errors.As(err, &r) {
		return refuse(r.Name)
	}
	if errors.Is(caller.Err(), context.Canceled) {
		return context.Canceled
	}
	if certificateError(err) {
		return refuse(CertificateNotVerified)
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return refuse(Timeout)
	}
	if text := err.Error(); strings.Contains(text, "response headers exceeded") ||
		strings.Contains(text, "header list larger") {
		// net/http names no error value for headers over the bound; its
		// text is matched and dropped.
		return refuse(ResponseTooLarge)
	}
	return refuse(ConnectFailed)
}

// certificateError reports whether err is a certificate that did not verify.
func certificateError(err error) bool {
	var (
		verify   *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	return errors.As(err, &verify) || errors.As(err, &unknown) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}
