// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// ErrNoFlow is a callback whose state matches no live flow: answered with a
// page that says the link has expired, and no redirect.
var ErrNoFlow = errors.New("signin: no flow has this state")

// The errors a callback sends a browser back with.
const (
	backAccessDenied = "access_denied"
	backFailed       = "sign_in_failed"
	backExpired      = "flow_expired"
)

// secret is 32 random bytes in base64url, for a state, a verifier and a
// finish code.
func secret() string {
	b := make([]byte, 32)
	// crypto/rand.Read does not fail: it aborts the process when the
	// system's source is unavailable.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hash is the SHA-256 a value is kept as.
func hash(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

// challengeOf is the S256 challenge of a verifier.
func challengeOf(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Begin starts a sign-in for a connection (specs/007-sign-in.md): it
// records the plan in a flow with a state, kept only as its hash, and a
// proof-key verifier, sealed, and answers the address to send the person
// to. The caller stores the flow, which replaces a live one.
func (s *Signin) Begin(c store.Connection, p Plan, returnTo string) (string, store.Flow, error) {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", store.Flow{}, unsupported("authorization_endpoint")
	}
	state, verifier := secret(), secret()
	f := store.Flow{
		ID: s.newID(id.Flow), Connection: c.ID, StateHash: hash(state),
		Issuer: p.Issuer, AuthorizationEndpoint: p.AuthorizationEndpoint, TokenEndpoint: p.TokenEndpoint,
		RevocationEndpoint: p.RevocationEndpoint, IssParameterSupported: p.IssParameterSupported,
		ClientID: p.ClientID, RedirectURI: s.RedirectURI(), Resource: p.Resource, Scopes: p.Scopes,
		ReturnTo: returnTo, CreatedAt: s.now(), ExpiresAt: s.now().Add(FlowTime),
	}
	sealed, err := s.Sealer.Seal([]byte(verifier), store.VerifierBinding(f.ID, c.ID))
	switch {
	case errors.Is(err, store.ErrNoSealingKey):
		return "", store.Flow{}, apierr.Fail(apierr.CodeSealingUnavailable, "no_sealing_key")
	case err != nil:
		return "", store.Flow{}, apierr.Internal(err)
	}
	f.Verifier = sealed
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", f.RedirectURI)
	q.Set("code_challenge", challengeOf(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if p.Resource != "" {
		q.Set("resource", p.Resource)
	}
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), f, nil
}

// back is the flow's return_to with the connection and one member added.
func back(f store.Flow, member, value string) string {
	u, err := url.Parse(f.ReturnTo)
	if err != nil {
		// A return_to was held to its rule when the flow was made.
		return f.ReturnTo
	}
	q := u.Query()
	q.Set("connection", f.Connection)
	q.Set(member, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// end ends a flow: its time is set to now, so the next sweep takes it as a
// flow that ran out, and no callback or confirm matches it again.
func (s *Signin) end(ctx context.Context, f store.Flow, outcome string) {
	f.ExpiresAt, f.StateHash, f.FinishHash = s.now(), nil, nil
	if err := s.Store.Flows().Put(ctx, f); err != nil {
		s.log().WarnContext(ctx, "an ended flow was not written; it runs out by its time", "flow", f.ID, "error", err.Error())
	}
	s.log().InfoContext(ctx, "a sign-in ended", "flow", f.ID, "connection", f.Connection, "outcome", outcome)
}

// Callback takes the answer the other service sent a person's browser back
// with (specs/007-sign-in.md): it finds the flow by its state, validates
// iss before the code goes anywhere, exchanges the code at the flow's token
// endpoint, reads the account once, seals the tokens with the flow, and
// mints the finish code. It answers where the browser goes: the flow's
// return_to and no other address. ErrNoFlow is a state no live flow has.
func (s *Signin) Callback(ctx context.Context, q url.Values) (string, error) {
	state := q.Get("state")
	if state == "" {
		return "", ErrNoFlow
	}
	f, err := s.Store.Flows().ByState(ctx, hash(state))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", ErrNoFlow
	case err != nil:
		return "", apierr.Internal(err)
	}
	if !s.now().Before(f.ExpiresAt) {
		s.end(ctx, f, backExpired)
		return back(f, "error", backExpired), nil
	}
	row, err := s.Store.Connections().Get(ctx, f.Connection)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", ErrNoFlow
	case err != nil:
		return "", apierr.Internal(err)
	}
	conn, err := s.Resolve(ctx, row.Connector)
	if err != nil {
		s.end(ctx, f, backFailed)
		return back(f, "error", backFailed), nil
	}
	if !issAccepted(q, f, conn) {
		s.end(ctx, f, backFailed)
		return back(f, "error", backFailed), nil
	}
	if e := q.Get("error"); e != "" {
		outcome := backFailed
		if e == backAccessDenied {
			outcome = backAccessDenied
		}
		s.end(ctx, f, outcome)
		return back(f, "error", outcome), nil
	}
	pending, err := s.exchange(ctx, row, conn, f, q.Get("code"))
	if err != nil {
		s.log().WarnContext(ctx, "a code was not exchanged", "flow", f.ID, "reason", reasonOf(err))
		s.end(ctx, f, backFailed)
		return back(f, "error", backFailed), nil
	}
	finish := secret()
	f.Pending, f.FinishHash, f.StateHash = pending, hash(finish), nil
	f.ExpiresAt = s.now().Add(ConfirmTime)
	if err := s.Store.Flows().Put(ctx, f); err != nil {
		return "", apierr.Internal(err)
	}
	return back(f, "code", finish), nil
}

// issAccepted is the iss rule of specs/007-sign-in.md, with its last row
// narrowed: an iss present is compared with the recorded issuer as strings;
// an absent one is refused when the metadata says iss is sent, and accepted
// otherwise only from a server the catalog names, by its issuer or by its
// endpoints.
func issAccepted(q url.Values, f store.Flow, conn Connector) bool {
	if values, ok := q["iss"]; ok {
		return f.Issuer != "" && len(values) == 1 && values[0] == f.Issuer
	}
	if f.IssParameterSupported {
		return false
	}
	return conn.Auth.Discovery == catalog.DiscoveryNone || (conn.Auth.Issuer != "" && conn.Auth.Issuer == f.Issuer)
}

// exchange trades a code at the flow's token endpoint, with the verifier,
// the redirect address, the resource and the client, reads the account
// once, and seals the tokens as the flow's pending credential, bound as the
// connection's credential will be.
func (s *Signin) exchange(ctx context.Context, row store.Connection, conn Connector, f store.Flow, code string) (store.SealedCredential, error) {
	if code == "" {
		return store.SealedCredential{}, &tokenError{Code: "no_code"}
	}
	verifier, err := s.Sealer.Open(f.Verifier, store.VerifierBinding(f.ID, f.Connection))
	if err != nil {
		return store.SealedCredential{}, err
	}
	c, err := s.clientAt(ctx, conn, f.Issuer, f.ClientID)
	if err != nil {
		return store.SealedCredential{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {f.RedirectURI}}
	if f.Resource != "" {
		form.Set("resource", f.Resource)
	}
	a, err := s.token(ctx, f.TokenEndpoint, conn.Ports(), form, map[string]string{"code": code, "code_verifier": string(verifier)}, c)
	clear(verifier)
	if err != nil {
		if isCode(err, errInvalidClient) {
			s.forget(ctx, f.Issuer, f.ClientID)
		}
		return store.SealedCredential{}, err
	}
	meta := s.metaOf(store.Meta{
		Issuer: f.Issuer, TokenEndpoint: f.TokenEndpoint, RevocationEndpoint: f.RevocationEndpoint,
		Resource: f.Resource, ClientID: f.ClientID, Scopes: f.Scopes,
	}, a)
	meta.Account = s.account(ctx, conn, a.AccessToken)
	return s.seal(row, conn, store.Secrets{AccessToken: a.AccessToken, RefreshToken: a.RefreshToken}, meta)
}

// Confirm makes a connection usable with the finish code its sign-in's
// browser brought back (specs/007-sign-in.md): in one transaction the
// flow's pending credential and scopes become the connection's, its reason
// is cleared and the flow is deleted. A wrong code ends the flow; a late
// one and no flow are 410; no callback yet is 409.
func (s *Signin) Confirm(ctx context.Context, c store.Connection, code string) error {
	f, err := s.Store.Flows().Get(ctx, c.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeFlowExpired, "")
	case err != nil:
		return apierr.Internal(err)
	}
	if !s.now().Before(f.ExpiresAt) {
		return apierr.Fail(apierr.CodeFlowExpired, "")
	}
	if len(f.FinishHash) == 0 {
		return notConnected(c.State, "not_confirmed")
	}
	if subtle.ConstantTimeCompare(hash(code), f.FinishHash) != 1 {
		s.end(ctx, f, "invalid_code")
		return apierr.OnField(apierr.CodeInvalidCode, "code", "")
	}
	meta, err := store.DecodeMeta(f.Pending.Meta)
	if err != nil {
		return apierr.Internal(err)
	}
	err = s.Store.Tx(ctx, func(tx store.Tx) error {
		if _, err := tx.Credentials().Put(ctx, c.ID, f.Pending); err != nil {
			return err
		}
		if err := tx.Connections().Move(ctx, c.ID, store.StatePending, store.StateConnected, ""); err != nil {
			return err
		}
		if err := tx.Connections().Describe(ctx, c.ID, store.Account{Account: meta.Account, Scopes: meta.Scopes, ExpiresAt: meta.RefreshExpiresAt}); err != nil {
			return err
		}
		return tx.Flows().Delete(ctx, c.ID)
	})
	switch {
	case errors.Is(err, store.ErrStateMoved), errors.Is(err, store.ErrIllegalMove):
		return notConnected(c.State, "state_moved")
	case err != nil:
		return apierr.Internal(err)
	}
	s.mint.forget(c.ID)
	s.log().InfoContext(ctx, "a sign-in ended", "flow", f.ID, "connection", c.ID, "outcome", "connected")
	return nil
}

// Reconnect plans a new sign-in for a stored connection
// (specs/007-sign-in.md): discovery again, asking for the union of the
// scopes its credential was granted and the ones named, so nothing granted
// before is lost. Its issuer is the one recorded with its credential at its
// first confirm and does not change: a discovery that finds another is 422
// sign_in_unsupported with issuer_changed, and nothing changes.
func (s *Signin) Reconnect(ctx context.Context, c store.Connection, conn Connector, named []string) (Plan, error) {
	var issuer string
	var granted []string
	held := false
	sealed, _, err := s.Store.Credentials().Get(ctx, c.ID)
	switch {
	case err == nil:
		meta, err := store.DecodeMeta(sealed.Meta)
		if err != nil {
			return Plan{}, apierr.Internal(err)
		}
		issuer, granted, held = meta.Issuer, meta.Scopes, true
	case !errors.Is(err, store.ErrNotFound):
		return Plan{}, apierr.Internal(err)
	}
	p, err := s.Discover(ctx, conn, union(granted, named))
	if err != nil {
		return Plan{}, err
	}
	if held && p.Issuer != issuer {
		return Plan{}, unsupported("issuer_changed")
	}
	return p, nil
}

// ReturnAllowed reports whether a return_to is one of the addresses a
// browser may return to (specs/007-sign-in.md): an absolute URL with no
// user part and no fragment that equals an entry, or starts with an entry
// that ends in a slash, compared as strings, and has no dot segment,
// encoded or not.
func ReturnAllowed(returnTo string, entries []string) bool {
	u, err := url.Parse(returnTo)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(returnTo, "#") {
		return false
	}
	for seg := range strings.SplitSeq(u.EscapedPath(), "/") {
		if d, err := url.PathUnescape(seg); err != nil || d == "." || d == ".." {
			return false
		}
	}
	for _, e := range entries {
		if returnTo == e || (strings.HasSuffix(e, "/") && strings.HasPrefix(returnTo, e)) {
			return true
		}
	}
	return false
}
