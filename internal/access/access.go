// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package access is ponsd's side of specs/004-identity-and-authorization.md:
// who a caller is, and who decides what that caller may do.
//
// Who is an Authenticator. A bearer is verified against one of the issuers
// PONS_OIDC_ISSUERS lists, through latere.ai/x/pkg/authkit/jwt, and becomes
// a Caller: the rendered subject, its two halves apart, and every claim of
// the token verbatim. No claim is read for meaning here.
//
// What is an Authorizer. One question per request, in the vocabulary of
// latere.ai/x/pons/authorizer, goes to the endpoint PONS_AUTHORIZER_URL
// names through the client of latere.ai/x/pkg/authz, which caches, retries
// and fails closed by that contract's rules. With no endpoint configured the
// owner policy of this package answers. A handler cannot tell which is in
// force.
//
// A handler is written in four steps: authenticate, build the resource from
// the request and the stored object, ask, and act within the decision.
// Routes says which action each route of the contract asks.
package access

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
)

// Caller is a verified bearer. Subject is the one string an owner field, a
// record and an authorizer request carry: the issuer and the sub joined by a
// pipe. Claims is every claim of the token, verbatim. It is handed to the
// authorizer as it came and read by nothing in Pons.
type Caller struct {
	Subject string
	Issuer  string
	Sub     string
	Claims  map[string]any
}

// Authenticator turns a request's bearer into a caller.
type Authenticator interface {
	// Authenticate verifies the request's bearer: ErrMissingToken for a
	// request that carries none, and a *TokenError for one that is refused.
	Authenticate(r *http.Request) (Caller, error)
}

// Authorizer answers one question about one caller.
type Authorizer interface {
	// Authorize asks whether the caller may do the question's action to its
	// resource. A deny is a Decision and not an error. An error is a
	// question that got no decision, ErrUnavailable, and the request fails
	// closed with it.
	Authorize(ctx context.Context, caller Caller, q Question) (Decision, error)
}

// The errors of a question.
var (
	// ErrMissingToken is a request that carries no bearer.
	ErrMissingToken = errors.New("access: the request carries no bearer token")
	// ErrUnavailable is a question that got no well-formed answer: the
	// authorizer did not answer, answered another status, a body that does
	// not parse or carries no allow, limits that cannot be read, or a
	// filter that cannot be applied.
	ErrUnavailable = errors.New("access: the authorizer gave no decision")
)

// TokenError is a bearer the verifier refused. Reason is the verifier's
// word for why, from jwt.ReasonOf, and never a part of the token.
type TokenError struct {
	Reason    string
	Retryable bool
	err       error
}

func (e *TokenError) Error() string { return "access: the bearer token was refused: " + e.Reason }

// Unwrap is the verifier's own error.
func (e *TokenError) Unwrap() error { return e.err }

// Question is what a handler asks: the action its route is given in
// Routes, the resource built from the request and the stored object, and
// what the authorizer learns about the request itself.
type Question struct {
	Action   string
	Resource authz.Resource
	Request  authz.Caller
}

// Ask builds the question a request asks.
func Ask(r *http.Request, action string, resource authz.Resource) Question {
	return Question{Action: action, Resource: resource, Request: RequestInfo(r)}
}

// RequestInfo is what the authorizer is told about the request: its id when
// the request carries one, the peer address as the server sees it, and the
// user agent.
func RequestInfo(r *http.Request) authz.Caller {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// An address with no port is already the host.
		host = r.RemoteAddr
	}
	return authz.Caller{ID: r.Header.Get("X-Request-Id"), IP: host, UserAgent: r.UserAgent()}
}

// Decision is the answer to a question.
type Decision struct {
	// Allow says whether the caller may. Nothing else is set on a deny but
	// Reason.
	Allow bool
	// Reason is the authorizer's own word for its answer. On a deny it is
	// the developer detail of the refusal and never the sentence a person
	// reads.
	Reason string
	// Limits are what the request is held to, read from the allow of the
	// actions that carry them: a connect and an add (the owner, the cap,
	// the connectors), and a use (read only, tools, refs, the rate). Every
	// other action's limits are not read and are zero here.
	Limits authorizer.Limits
	// Filter narrows a list to owners. Nil on an allow of a list is the
	// caller's own.
	Filter *authz.Filter
}

// Owners are the owners a list may show: the filter's, or the caller's own
// when the allow named none, narrowed by the owner the request named, which
// never widens them.
func (d Decision) Owners(caller Caller, requested string) []string {
	owners := []string{caller.Subject}
	if d.Filter != nil {
		owners = slices.Clone(d.Filter.Owners)
	}
	if requested == "" {
		return owners
	}
	if slices.Contains(owners, requested) {
		return []string{requested}
	}
	return nil
}

// asker asks one authz.Authorizer, the shared client over the operator's
// endpoint or the owner policy, and reads its answer. The cache, the retry
// and the timeout are the client's. Nothing here decides.
type asker struct{ inner authz.Authorizer }

// NewAuthorizer wraps whichever authorizer a server runs.
func NewAuthorizer(inner authz.Authorizer) Authorizer { return &asker{inner: inner} }

func (a *asker) Authorize(ctx context.Context, caller Caller, q Question) (Decision, error) {
	// A question outside the vocabulary, or about another kind than its
	// action acts on, is a mistake in a handler. It is refused before it is
	// sent, so the mistake cannot be answered with an allow.
	if kind := authorizer.Kind(q.Action); kind == "" || kind != q.Resource.Kind {
		return Decision{}, fmt.Errorf("access: the action %q does not act on the kind %q", q.Action, q.Resource.Kind)
	}
	d, err := a.inner.Authorize(ctx, envelope(caller, q))
	if err != nil {
		// The error underneath may name the endpoint, so it is wrapped for
		// the log and never shown to the caller.
		return Decision{}, fmt.Errorf("%w: %s: %w", ErrUnavailable, q.Action, err)
	}
	if !d.Allow {
		return Decision{Reason: reasonOf(d)}, nil
	}
	out := Decision{Allow: true, Reason: d.Reason, Filter: d.Filter}
	if d.Filter != nil && len(d.Filter.Labels) > 0 {
		// Nothing in Pons is labeled, so a filter by labels cannot be
		// applied, and a list it cannot narrow is no answer.
		return Decision{}, fmt.Errorf("%w: the filter of %s names labels", ErrUnavailable, q.Action)
	}
	if readsLimits(q) {
		limits, err := authorizer.DecodeLimits(d)
		if err != nil {
			return Decision{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		out.Limits = held(q, limits)
	}
	return out, nil
}

// readsLimits reports whether the allow of a question carries limits Pons
// holds: a connect, an add and a use. The limits of any other allow are not
// read.
func readsLimits(q Question) bool {
	switch q.Action {
	case authorizer.ActionConnectionCreate:
		return q.Resource.ID == ""
	case authorizer.ActionConnectorCreate, authorizer.ActionConnectionUse:
		return true
	}
	return false
}

// held keeps the members an action's allow is read for.
func held(q Question, l authorizer.Limits) authorizer.Limits {
	switch q.Action {
	case authorizer.ActionConnectionCreate:
		return authorizer.Limits{Owner: l.Owner, MaxConnections: l.MaxConnections, Connectors: l.Connectors}
	case authorizer.ActionConnectorCreate:
		return authorizer.Limits{Owner: l.Owner}
	}
	return authorizer.Limits{ReadOnly: l.ReadOnly, Tools: l.Tools, Refs: l.Refs, Requests: l.Requests, CallsPerMinute: l.CallsPerMinute}
}

// envelope is what one call carries: the caller's subject and its claims
// verbatim, the action, the resource, and what is known of the request.
func envelope(c Caller, q Question) authz.Request {
	claims := c.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return authz.Request{
		Subject: c.Subject, Issuer: c.Issuer, Sub: c.Sub, Claims: claims,
		Action: q.Action, Resource: q.Resource, Request: q.Request,
	}
}

// reasonOf is the authorizer's reason, or a word when it named none, so a
// refusal always says something.
func reasonOf(d authz.Decision) string {
	if d.Reason == "" {
		return "no reason given"
	}
	return d.Reason
}

// Check sends the probe every authorizer denies and reports one that
// answered nothing or allowed it. An allow is an endpoint that does not
// read the request.
func Check(ctx context.Context, a authz.Authorizer) error {
	return authz.Check(ctx, a, authorizer.ActionConnectionRead, authorizer.KindConnection)
}
