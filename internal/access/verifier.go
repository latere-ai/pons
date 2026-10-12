// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"latere.ai/x/pkg/authkit/jwt"
	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/bearer"
)

// ClockSkew is how far an issuer's clock may differ from this server's: a
// token is read until this long past its exp and from this long before its
// nbf.
const ClockSkew = 30 * time.Second

// VerifierOptions configures a Verifier. Issuers and Audiences are
// PONS_OIDC_ISSUERS and PONS_OIDC_AUDIENCE.
type VerifierOptions struct {
	// Issuers are the issuers whose tokens are accepted. Each one's key set
	// is discovered from the issuer itself.
	Issuers []string
	// Audiences are the audiences a token may be addressed to. The first is
	// the primary one.
	Audiences []string
	// HTTP reads the discovery documents and the key sets: the operator
	// client. Required.
	HTTP *http.Client
	// Now is the clock. Nil takes time.Now.
	Now func() time.Time
}

// Verifier verifies a bearer against the listed issuers. Each issuer answers
// for its own tokens alone: the token's iss selects the key set its
// signature is checked against. Nothing here calls an issuer for anything
// but its discovery document and its key set.
type Verifier struct {
	issuers   []string
	audiences []string
	validator *jwt.Validator
}

// NewVerifier builds the verifier. It reads nothing from the network: Warm
// does, for a server that wants an unreachable issuer named at start.
func NewVerifier(o VerifierOptions) (*Verifier, error) {
	if len(o.Issuers) == 0 {
		return nil, errors.New("PONS_OIDC_ISSUERS names no issuer: a server verifies its callers against an issuer")
	}
	if len(o.Audiences) == 0 || slices.Contains(o.Audiences, "") {
		// A verifier with no audience would accept a token addressed to any
		// other service of the same issuer.
		return nil, errors.New("PONS_OIDC_AUDIENCE names no audience")
	}
	if o.HTTP == nil {
		return nil, errors.New("access: the verifier is given no client to read key sets with")
	}
	v := &Verifier{audiences: slices.Clone(o.Audiences)}
	for _, raw := range o.Issuers {
		v.issuers = append(v.issuers, strings.TrimRight(raw, "/"))
	}
	v.validator = jwt.New(jwt.Config{
		Issuers:    v.issuers,
		Audiences:  v.audiences,
		HTTPClient: o.HTTP,
		ClockSkew:  ClockSkew,
		Now:        o.Now,
		// A personal access token carries the grants its holder chose. The
		// promise to apply them is kept where the decision is made: the
		// owner policy narrows its answer by the grants, and an authorizer
		// built on the shared scaffold does the same.
		ReadsGrants: true,
	})
	return v, nil
}

// Issuers lists the issuers this verifier accepts, in configured order.
func (v *Verifier) Issuers() []string { return slices.Clone(v.issuers) }

// Warm reads every issuer's key set once, so the first request does not pay
// for the fetch. The error names each issuer that did not answer; the
// verifier works either way and reads the set again when a token of that
// issuer arrives.
func (v *Verifier) Warm(ctx context.Context) error { return v.validator.Warm(ctx) }

// Authenticator is the same validator behind the interface the shared
// conformance suite drives.
func (v *Verifier) Authenticator() *jwt.Authenticator { return jwt.NewAuthenticator(v.validator) }

// Authenticate reads the bearer of a request and verifies it.
func (v *Verifier) Authenticate(r *http.Request) (Caller, error) {
	raw, ok := bearer.FromRequest(r)
	if !ok || raw == "" {
		return Caller{}, ErrMissingToken
	}
	return v.Verify(raw)
}

// Verify verifies one bearer: its signature against the key set of the
// issuer it names, iss among the listed issuers, aud among the audiences,
// and exp and nbf within the skew. A token that carries iat is also held to
// the shared verifier's age bound.
func (v *Verifier) Verify(raw string) (Caller, error) {
	verified, err := v.validator.Validate(raw)
	if err != nil {
		// The reason is the word every service on the shared verifier
		// writes, and never a part of the token.
		reason := jwt.ReasonOf(err)
		word := string(reason)
		if word == "" {
			word = "refused"
		}
		return Caller{}, &TokenError{Reason: word, Retryable: reason == jwt.ReasonIssuerUnavailable, err: err}
	}
	// Every claim, as the issuer wrote it, for the authorizer to read. The
	// token is verified, so this decodes what the signature covers.
	var claims map[string]any
	if err := jwt.DecodePayload(raw, &claims); err != nil {
		return Caller{}, &TokenError{Reason: string(jwt.ReasonMalformed), err: err}
	}
	issuer := strings.TrimRight(verified.Iss, "/")
	return Caller{Subject: authz.Subject(issuer, verified.Sub), Issuer: issuer, Sub: verified.Sub, Claims: claims}, nil
}
