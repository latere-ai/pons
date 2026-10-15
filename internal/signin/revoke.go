// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
)

// Disconnect removes a connection (specs/007-sign-in.md): it opens the
// credential, removes the row, the ciphertext and the flow in one
// transaction, and then revokes at the revocation endpoint recorded with
// the credential, once, best effort, when no other credential holds its
// grant. A credential nothing can open is removed without revoking; a
// pasted key cannot be revoked.
func (s *Signin) Disconnect(ctx context.Context, c store.Connection) error {
	var held *Opened
	if c.Auth == catalog.AuthOAuth {
		conn, err := s.Resolve(ctx, c.Connector)
		if err != nil && !errors.Is(err, ErrNoConnector) {
			return apierr.Internal(err)
		}
		o, err := Open(ctx, s.Store, s.Sealer, c, conn)
		switch {
		case err == nil:
			held = &o
		case errors.Is(err, store.ErrNotFound):
		default:
			s.log().WarnContext(ctx, "a credential did not open; it is removed without revoking", "connection", c.ID, "reason", apierr.Classify(err).Reason)
		}
	}
	if err := s.Store.Connections().Delete(ctx, c.ID); err != nil {
		return err
	}
	s.mint.forget(c.ID)
	if held != nil {
		s.revokeLast(ctx, held.Connector, held.Meta, held.Secrets, "connection", c.ID)
	}
	return nil
}

// revokeLast revokes a credential already removed from the store, at the
// revocation endpoint its meta records, unless another credential still
// holds its grant (specs/007-sign-in.md). A server may end the whole grant
// at the revocation of any of its tokens, as Google does, which would end
// the other connections of the person's account at that client.
//
// The holders are counted after the removal has committed, in a statement
// of their own. Of two removals of a grant's last two holders at once, the
// one that counts later sees the other's removal and revokes; both may,
// and a second revocation of an ended grant only fails. Counting inside
// the removal's transaction would let each see the other's row, not yet
// deleted, and both skip. A meta with no account names no person, so its
// grant has no holder to wait for and is revoked. attrs name what the
// credential was, for the log.
func (s *Signin) revokeLast(ctx context.Context, conn Connector, meta store.Meta, secrets store.Secrets, attrs ...any) {
	if meta.RevocationEndpoint == "" {
		return
	}
	n, err := s.Store.Credentials().GrantHolders(ctx, meta.Grant())
	switch {
	case err != nil:
		s.log().WarnContext(ctx, "a revocation was skipped: the holders of its grant were not counted",
			append(attrs, "outcome", "skipped", "reason", "grant_not_counted", "error", err.Error())...)
		return
	case n > 0:
		s.log().InfoContext(ctx, "a revocation was skipped: other credentials hold the same grant",
			append(attrs, "outcome", "skipped", "reason", "grant_held", "count", n)...)
		return
	}
	s.revoke(ctx, conn, meta, secrets, attrs...)
}

// revoke revokes a credential's tokens (RFC 7009): the refresh token, or
// else the access token, with its hint and the client, once, in 10 seconds.
// A failure is logged without the token and changes nothing.
func (s *Signin) revoke(ctx context.Context, conn Connector, meta store.Meta, secrets store.Secrets, attrs ...any) {
	token, hint := secrets.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = secrets.AccessToken, "access_token"
	}
	if token == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	c, err := s.clientAt(ctx, conn, meta.Issuer, meta.ClientID, meta.TokenEndpoint)
	if err == nil {
		var status int
		status, _, err = s.post(ctx, meta.RevocationEndpoint, conn.Ports(), url.Values{"token_type_hint": {hint}}, map[string]string{"token": token}, c)
		if err == nil && (status < 200 || status > 299) {
			err = &tokenError{Code: "status_" + strconv.Itoa(status)}
		}
	}
	if err != nil {
		s.log().WarnContext(ctx, "a revocation failed", append(attrs, "outcome", "failed", "reason", reasonOf(err))...)
		return
	}
	s.log().InfoContext(ctx, "a credential was revoked", append(attrs, "outcome", "revoked")...)
}

// Sweep takes the flows past their time, each handed by the store to one
// sweeper (specs/007-sign-in.md): it discards their pending credentials and
// revokes each whose grant has no other holder, deletes a pending
// connection that never had a credential,
// and returns one being reconnected to connected, or to needs_reconnect
// when it has a reason. It answers how many flows it took.
func (s *Signin) Sweep(ctx context.Context) (int, error) {
	n := 0
	for {
		flows, err := s.Store.Flows().TakeExpired(ctx, s.now(), sweepBatch)
		if err != nil {
			return n, err
		}
		for _, f := range flows {
			if err := s.settle(ctx, f); err != nil {
				s.log().WarnContext(ctx, "an expired flow's connection was not settled", "flow", f.ID, "connection", f.Connection, "error", err.Error())
			}
		}
		n += len(flows)
		if len(flows) < sweepBatch {
			return n, nil
		}
	}
}

// settle is one expired flow, which the store already deleted: its pending
// credential revoked unless another credential holds its grant, the
// connection's own among them while a reconnect keeps it, and its
// connection deleted or returned to the state it left.
func (s *Signin) settle(ctx context.Context, f store.Flow) error {
	row, err := s.Store.Connections().Get(ctx, f.Connection)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	conn, err := s.Resolve(ctx, row.Connector)
	if err != nil && !errors.Is(err, ErrNoConnector) {
		return err
	}
	if !f.Pending.Sealed.Zero() {
		meta, err := store.DecodeMeta(f.Pending.Meta)
		if err != nil {
			return err
		}
		plain, err := s.Sealer.Open(f.Pending.Sealed, store.CredentialBinding(row.ID, row.Owner, row.Auth, meta, conn.AddedURL))
		if err == nil {
			secrets, derr := store.DecodeSecrets(plain)
			clear(plain)
			if derr == nil {
				s.revokeLast(ctx, conn, meta, secrets, "flow", f.ID, "connection", row.ID)
			}
		}
	}
	s.log().InfoContext(ctx, "a sign-in ended", "flow", f.ID, "connection", row.ID, "outcome", backExpired)
	if row.State != store.StatePending {
		return nil
	}
	if _, _, err := s.Store.Credentials().Get(ctx, row.ID); errors.Is(err, store.ErrNotFound) {
		return s.Store.Connections().Delete(ctx, row.ID)
	} else if err != nil {
		return err
	}
	to := store.StateConnected
	if row.Reason != "" {
		to = store.StateNeedsReconnect
	}
	err = s.Store.Connections().Move(ctx, row.ID, store.StatePending, to, "")
	if errors.Is(err, store.ErrStateMoved) {
		// A confirm or a reconnect got there first.
		return nil
	}
	return err
}

// maxAccountAnswer bounds the answer of the account read.
const maxAccountAnswer = 1 << 20

// account reads the account a connection acts as, once, after the code
// exchange (specs/013-github-connector.md): a GET of the entry's account
// url with the new access token, bound to the connector's hosts, and the
// string at the top-level member it names. A failure leaves it empty and
// fails nothing.
func (s *Signin) account(ctx context.Context, conn Connector, token string) string {
	a := conn.Auth.Account
	if a == nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.Dial.Do(ctx, dial.Request{
		HTTP:    req,
		Secrets: []dial.Secret{{Value: token, Header: "Authorization", Format: "Bearer {value}", Hosts: catalog.Matcher(conn.HostPatterns())}},
		Ports:   conn.Ports(), Timeout: tokenTimeout, MaxBody: maxAccountAnswer,
	})
	if err != nil {
		s.log().InfoContext(ctx, "the account was not read", "reason", reasonOf(err))
		return ""
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	var doc map[string]any
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &doc) != nil {
		s.log().InfoContext(ctx, "the account was not read", "status", resp.StatusCode)
		return ""
	}
	name, _ := doc[a.Field].(string)
	return name
}

// forget drops the tokens minted for a connection.
func (m *mints) forget(connection string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.tokens {
		if len(k) > len(connection) && k[:len(connection)+1] == connection+"@" {
			delete(m.tokens, k)
		}
	}
	delete(m.locks, connection)
}
