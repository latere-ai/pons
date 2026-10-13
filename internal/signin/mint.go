// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
)

// Mint is the access token of a client_credentials connection: one the
// process minted before and keeps until 60 seconds before its expiry, or a
// new one from the entry's token endpoint, one request per connection at a
// time. renew drops the kept one first, after the connector refused it. The
// token is kept in memory and never stored. A client the endpoint refuses
// moves the connection to needs_reconnect with credential_refused.
func (s *Signin) Mint(ctx context.Context, o Opened, renew bool) (string, error) {
	key := o.Connection.ID + "@" + strconv.FormatInt(o.Version, 10)
	lock := s.mint.lock(o.Connection.ID)
	lock.Lock()
	defer lock.Unlock()
	if renew {
		s.mint.drop(key)
	} else if tok, ok := s.mint.get(key, s.now()); ok {
		return tok, nil
	}
	a, err := s.clientGrant(ctx, o.Meta, o.Connector.Ports(), o.Secrets.ClientSecret)
	switch {
	case isCode(err, errInvalidClient):
		return "", Refused(ctx, s.Store, o.Connection, store.ReasonCredentialRefused)
	case err != nil:
		s.log().WarnContext(ctx, "a token was not minted", "connection", o.Connection.ID, "reason", reasonOf(err))
		return "", unavailable("mint_failed")
	}
	until := s.now().Add(mintedFor)
	if a.ExpiresIn > 0 {
		until = s.now().Add(time.Duration(a.ExpiresIn)*time.Second - RefreshAhead)
	}
	s.mint.put(key, minted{token: a.AccessToken, until: until})
	return a.AccessToken, nil
}

// FirstMint tries a client at connect, before it is stored: a client the
// endpoint refuses is 422 credential_refused, and an endpoint that cannot
// be reached 422 connector_unreachable. The token is dropped.
func (s *Signin) FirstMint(ctx context.Context, conn Connector, meta store.Meta, secret string) error {
	_, err := s.clientGrant(ctx, meta, conn.Ports(), secret)
	switch {
	case err == nil:
		return nil
	case isCode(err, errInvalidClient):
		return apierr.Fail(apierr.CodeCredentialRefused, errInvalidClient)
	}
	return apierr.Fail(apierr.CodeConnectorUnreachable, reasonOf(err))
}

// clientGrant asks the entry's token endpoint for a token with the
// client's own grant, the client by HTTP Basic, and the entry's scopes and
// audience.
func (s *Signin) clientGrant(ctx context.Context, meta store.Meta, ports []int, secret string) (answer, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(meta.Scopes) > 0 {
		form.Set("scope", strings.Join(meta.Scopes, " "))
	}
	if meta.Audience != "" {
		form.Set("audience", meta.Audience)
	}
	return s.token(ctx, meta.TokenEndpoint, ports, form, nil, client{ID: meta.ClientID, Secret: secret})
}

func (m *mints) lock(connection string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks == nil {
		m.locks = map[string]*sync.Mutex{}
	}
	l, ok := m.locks[connection]
	if !ok {
		l = &sync.Mutex{}
		m.locks[connection] = l
	}
	return l
}

func (m *mints) get(key string, now time.Time) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[key]
	if !ok || !now.Before(t.until) {
		delete(m.tokens, key)
		return "", false
	}
	return t.token, true
}

func (m *mints) put(key string, t minted) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens == nil {
		m.tokens = map[string]minted{}
	}
	m.tokens[key] = t
}

func (m *mints) drop(key string) {
	m.mu.Lock()
	delete(m.tokens, key)
	m.mu.Unlock()
}
