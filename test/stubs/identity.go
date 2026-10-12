// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
)

// Audience is the audience the stub issuer's tokens carry when the test
// names none: Pons's own default.
const Audience = "pons"

// Issuer is the stub issuer: a discovery document, a key set, and tokens
// minted for a subject, an audience and a session claim. Its switches are
// the shared stub's: Mint with an expiry in the past or another audience,
// Rotate, and Hang for an issuer that does not answer.
type Issuer struct {
	*issuertest.Server
}

// NewIssuer starts a stub issuer for the test.
func NewIssuer(t TB, opts ...issuertest.Option) *Issuer {
	t.Helper()
	d := &deferred{}
	srv := serveTLS(t, d)
	s := issuertest.NewHandler(append([]issuertest.Option{
		issuertest.WithIssuer(srv.URL), issuertest.WithDefaultAudience(Audience),
	}, opts...)...)
	d.set(s.Handler())
	t.Cleanup(s.Close)
	return &Issuer{Server: s}
}

// Token mints a token for the subject with the claims given beside the
// defaults: Extra carries a session claim, for one.
func (i *Issuer) Token(sub string, extra map[string]any) string {
	return i.Mint(issuertest.Claims{Sub: sub, Extra: extra})
}

// Subject is the rendered subject of a token the issuer mints for sub.
func (i *Issuer) Subject(sub string) string { return i.URL() + "|" + sub }

// Authorizer is the stub authorizer: the contract of
// specs/004-identity-and-authorization.md answered from a table of
// subject, action and resource, with the limits of an allow. It knows
// Pons's vocabulary, records every question, and has the shared stub's
// switches: Deny, Hang for no answer, Fail and FailBody for a malformed
// answer.
type Authorizer struct {
	*stub.Server
	url string
}

// NewAuthorizer starts a stub authorizer for the test. With no option it
// allows every subject; WithAllow narrows that.
func NewAuthorizer(t TB, opts ...stub.Option) *Authorizer {
	t.Helper()
	s := stub.NewHandler(append([]stub.Option{stub.WithVocabulary(authorizer.Vocabulary())}, opts...)...)
	srv := serveTLS(t, s.Handler())
	t.Cleanup(s.Close)
	return &Authorizer{Server: s, url: srv.URL}
}

// URL is the endpoint, the value PONS_AUTHORIZER_URL takes.
func (a *Authorizer) URL() string { return a.url }
