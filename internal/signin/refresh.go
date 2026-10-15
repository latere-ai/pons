// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"errors"
	"net/url"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
)

// unavailable is the 502 a call answers when the other service's token
// endpoint did not give it a token.
func unavailable(reason string) *apierr.Error {
	return &apierr.Error{Code: apierr.CodeConnectorUnavailable, Reason: reason}
}

// Due reports whether an opened oauth credential is refreshed before it is
// used: it has a refresh token, and its access token ends within a minute.
// A token whose answer gave no lifetime is refreshed only when the
// connector refuses it.
func (s *Signin) Due(o Opened) bool {
	return o.Connection.Auth == catalog.AuthOAuth && o.Secrets.RefreshToken != "" &&
		!o.Meta.AccessExpiresAt.IsZero() && !s.now().Add(RefreshAhead).Before(o.Meta.AccessExpiresAt)
}

// Fresh is the credential a call uses: the opened one, or a refreshed one
// when it is due.
func (s *Signin) Fresh(ctx context.Context, o Opened) (Opened, error) {
	if !s.Due(o) {
		return o, nil
	}
	return s.Refresh(ctx, o)
}

// Refresh trades an oauth credential's refresh token for new tokens, by one
// writer per connection (specs/007-sign-in.md). The caller that claims the
// lease asks the token endpoint with no transaction open; one that does not
// waits for the version to move and uses the new credential. It answers the
// credential to use. An invalid_grant moves the connection and answers its
// 409; any other failure releases the claim, moves nothing and answers 502.
func (s *Signin) Refresh(ctx context.Context, o Opened) (Opened, error) {
	if o.Secrets.RefreshToken == "" {
		return o, Refused(ctx, s.Store, o.Connection, store.ReasonRevoked)
	}
	creds := s.Store.Credentials()
	claimed, version, err := creds.ClaimRefresh(ctx, o.Connection.ID, refreshLease)
	if err != nil {
		return o, apierr.Internal(err)
	}
	if version != o.Version {
		// Another caller refreshed between the open and the claim.
		if claimed {
			if err := creds.ReleaseRefresh(ctx, o.Connection.ID); err != nil {
				return o, apierr.Internal(err)
			}
		}
		return s.reopen(ctx, o)
	}
	if !claimed {
		return s.await(ctx, o)
	}
	a, err := s.refreshGrant(ctx, o)
	if err != nil {
		if rerr := creds.ReleaseRefresh(context.WithoutCancel(ctx), o.Connection.ID); rerr != nil {
			return o, apierr.Internal(rerr)
		}
		if isCode(err, errInvalidGrant) {
			s.log().InfoContext(ctx, "a refresh was refused", "connection", o.Connection.ID, "outcome", "refused")
			return o, Refused(ctx, s.Store, o.Connection, store.ReasonRefreshRefused)
		}
		s.log().WarnContext(ctx, "a refresh failed", "connection", o.Connection.ID, "reason", reasonOf(err))
		return o, unavailable("refresh_failed")
	}
	next := o
	next.Secrets.AccessToken = a.AccessToken
	if a.RefreshToken != "" {
		next.Secrets.RefreshToken = a.RefreshToken
	}
	next.Meta = s.metaOf(o.Meta, a)
	sealed, err := s.seal(next.Connection, next.Connector, next.Secrets, next.Meta)
	if err != nil {
		return o, err
	}
	err = creds.CompleteRefresh(ctx, o.Connection.ID, version, sealed)
	switch {
	case errors.Is(err, store.ErrVersionMoved):
		// A confirm or a new key got there first: these tokens are dropped
		// and the stored credential is used.
		s.log().InfoContext(ctx, "a refresh lost to a newer credential", "connection", o.Connection.ID, "outcome", "superseded")
		return s.reopen(ctx, o)
	case err != nil:
		return o, apierr.Internal(err)
	}
	if !next.Meta.RefreshExpiresAt.IsZero() {
		if err := s.Store.Connections().Describe(ctx, o.Connection.ID, store.Account{
			Account: o.Connection.Account, Scopes: o.Connection.Scopes, ExpiresAt: next.Meta.RefreshExpiresAt,
		}); err != nil {
			s.log().WarnContext(ctx, "the refresh token's expiry was not written", "connection", o.Connection.ID, "error", err.Error())
		}
	}
	s.log().InfoContext(ctx, "a credential was refreshed", "connection", o.Connection.ID, "outcome", "ok")
	next.Version = version + 1
	return next, nil
}

// await waits for another caller's refresh: it reads the version every poll
// for up to the wait, and uses the new credential once it moved.
func (s *Signin) await(ctx context.Context, o Opened) (Opened, error) {
	wait, poll := s.waits()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return o, ctx.Err()
		case <-deadline.C:
			return o, &apierr.Error{Code: apierr.CodeConnectorUnavailable, Reason: "refresh_pending", Retryable: new(true)}
		case <-tick.C:
			_, version, err := s.Store.Credentials().Get(ctx, o.Connection.ID)
			if err != nil {
				return o, apierr.Internal(err)
			}
			if version != o.Version {
				return s.reopen(ctx, o)
			}
		}
	}
}

// reopen opens the credential the store holds now.
func (s *Signin) reopen(ctx context.Context, o Opened) (Opened, error) {
	next, err := Open(ctx, s.Store, s.Sealer, o.Connection, o.Connector)
	if err != nil {
		return o, err
	}
	return next, nil
}

// refreshGrant asks the recorded token endpoint for new tokens with the
// refresh token, the client and the resource.
func (s *Signin) refreshGrant(ctx context.Context, o Opened) (answer, error) {
	c, err := s.clientAt(ctx, o.Connector, o.Meta.Issuer, o.Meta.ClientID, o.Meta.TokenEndpoint)
	if err != nil {
		return answer{}, err
	}
	form := url.Values{"grant_type": {"refresh_token"}}
	if o.Meta.Resource != "" {
		form.Set("resource", o.Meta.Resource)
	}
	return s.token(ctx, o.Meta.TokenEndpoint, o.Connector.Ports(), form, map[string]string{"refresh_token": o.Secrets.RefreshToken}, c)
}

// metaOf is the meta of a credential after new tokens: the access token's
// expiry, the refresh token's when the answer names it, and the scopes it
// names, or the old ones.
func (s *Signin) metaOf(old store.Meta, a answer) store.Meta {
	m := old
	m.TokenType = "Bearer"
	m.AccessExpiresAt = time.Time{}
	if a.ExpiresIn > 0 {
		m.AccessExpiresAt = s.now().Add(time.Duration(a.ExpiresIn) * time.Second).UTC()
	}
	if a.RefreshExpiresIn > 0 {
		m.RefreshExpiresAt = s.now().Add(time.Duration(a.RefreshExpiresIn) * time.Second).UTC()
	}
	if scopes := scopeList(a.Scope); len(scopes) > 0 {
		m.Scopes = scopes
	}
	return m
}

// seal seals a credential under the binding of its connection.
func (s *Signin) seal(c store.Connection, conn Connector, secrets store.Secrets, meta store.Meta) (store.SealedCredential, error) {
	plain, err := secrets.Encode()
	if err != nil {
		return store.SealedCredential{}, apierr.Internal(err)
	}
	doc, err := store.EncodeMeta(meta)
	if err != nil {
		return store.SealedCredential{}, apierr.Internal(err)
	}
	sealed, err := s.Sealer.Seal(plain, store.CredentialBinding(c.ID, c.Owner, c.Auth, meta, conn.AddedURL))
	clear(plain)
	switch {
	case errors.Is(err, store.ErrNoSealingKey):
		return store.SealedCredential{}, apierr.Fail(apierr.CodeSealingUnavailable, "no_sealing_key")
	case err != nil:
		return store.SealedCredential{}, apierr.Internal(err)
	}
	return store.SealedCredential{Kind: c.Auth, Meta: doc, Sealed: sealed}, nil
}

// clientAt is the client a credential was issued to, with its secret read
// at use: the catalog's client when the entry names that id; a vouched-for
// added connector's own, whose sealed secret opens for the token endpoint
// its add found alone; a registration kept for the issuer at the shared
// callback or the issuer's own; or a public client.
func (s *Signin) clientAt(ctx context.Context, conn Connector, issuer, clientID, tokenEndpoint string) (client, error) {
	if cl := conn.Auth.Client; cl != nil && cl.ID == clientID {
		if conn.AddedURL != "" {
			if conn.ClientSecret.Zero() {
				return client{ID: clientID}, nil
			}
			secret, err := s.Sealer.Open(conn.ClientSecret, store.ConnectorClientBinding(conn.Ref, tokenEndpoint))
			if err != nil {
				return client{}, &apierr.Error{Code: apierr.CodeSealingUnavailable, Reason: "not_opened"}
			}
			return client{ID: clientID, Secret: string(secret)}, nil
		}
		if cl.Secret == nil {
			return client{ID: clientID}, nil
		}
		secret, err := cl.Secret.Resolve(s.LookupEnv)
		if err != nil {
			return client{}, unavailable("client_secret_unresolved")
		}
		return client{ID: clientID, Secret: secret}, nil
	}
	for _, redirect := range []string{s.RedirectURI(), s.CallbackFor(issuer)} {
		reg, err := s.Store.Registrations().Get(ctx, issuer, redirect)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return client{}, apierr.Internal(err)
		}
		if reg.ClientID != clientID {
			continue
		}
		if reg.Secret.Zero() {
			return client{ID: clientID}, nil
		}
		secret, err := s.Sealer.Open(reg.Secret, store.RegistrationBinding(reg.Issuer, reg.RedirectURI))
		if err != nil {
			return client{}, &apierr.Error{Code: apierr.CodeSealingUnavailable, Reason: "not_opened"}
		}
		return client{ID: clientID, Secret: string(secret)}, nil
	}
	return client{ID: clientID}, nil
}
