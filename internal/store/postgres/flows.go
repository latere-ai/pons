// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/pons/internal/store"
)

// --- flows ----------------------------------------------------------------

type flows struct{ v *view }

const flowCols = `id, connection, state_hash, issuer, authorization_endpoint, token_endpoint, revocation_endpoint,
       iss_parameter_supported, client_id, redirect_uri, resource, scopes::text, return_to, finish_hash,
       pending_kind, pending_meta::text, created_at, expires_at,
       verifier_key_id, verifier_wrapped_key, verifier_key_nonce, verifier_ciphertext, verifier_nonce,
       pending_key_id, pending_wrapped_key, pending_key_nonce, pending_ciphertext, pending_nonce`

func scanFlow(row pgx.Row) (store.Flow, error) {
	var f store.Flow
	var scopes string
	var pendingMeta *string
	v, p := &f.Verifier, &f.Pending.Sealed
	if err := row.Scan(&f.ID, &f.Connection, &f.StateHash, &f.Issuer, &f.AuthorizationEndpoint, &f.TokenEndpoint,
		&f.RevocationEndpoint, &f.IssParameterSupported, &f.ClientID, &f.RedirectURI, &f.Resource, &scopes,
		&f.ReturnTo, &f.FinishHash, &f.Pending.Kind, &pendingMeta, &f.CreatedAt, &f.ExpiresAt,
		&v.KeyID, &v.WrappedKey, &v.KeyNonce, &v.Ciphertext, &v.Nonce,
		&p.KeyID, &p.WrappedKey, &p.KeyNonce, &p.Ciphertext, &p.Nonce); err != nil {
		return store.Flow{}, err
	}
	s, err := list(scopes)
	if err != nil {
		return store.Flow{}, err
	}
	f.Scopes = s
	if pendingMeta != nil {
		f.Pending.Meta = raw(*pendingMeta)
	}
	f.CreatedAt, f.ExpiresAt = f.CreatedAt.UTC(), f.ExpiresAt.UTC()
	return f, nil
}

func (x flows) Put(ctx context.Context, f store.Flow) error {
	scopes, err := jsonText(f.Scopes, "[]")
	if err != nil {
		return err
	}
	var pendingMeta any
	if len(f.Pending.Meta) > 0 {
		text, err := jsonText(f.Pending.Meta, "{}")
		if err != nil {
			return err
		}
		pendingMeta = text
	}
	v, p := f.Verifier, f.Pending.Sealed
	// The flow replaces the live flow of its connection, in one statement.
	_, err = x.v.q.Exec(ctx, `
INSERT INTO flows (id, connection, state_hash, issuer, authorization_endpoint, token_endpoint, revocation_endpoint,
                   iss_parameter_supported, client_id, redirect_uri, resource, scopes, return_to, finish_hash,
                   pending_kind, pending_meta, created_at, expires_at,
                   verifier_key_id, verifier_wrapped_key, verifier_key_nonce, verifier_ciphertext, verifier_nonce,
                   pending_key_id, pending_wrapped_key, pending_key_nonce, pending_ciphertext, pending_nonce)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16::text::jsonb,
        coalesce($17::timestamptz, $29::timestamptz, now()), $18,
        $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
ON CONFLICT (connection) DO UPDATE SET
       id = EXCLUDED.id, state_hash = EXCLUDED.state_hash, issuer = EXCLUDED.issuer,
       authorization_endpoint = EXCLUDED.authorization_endpoint, token_endpoint = EXCLUDED.token_endpoint,
       revocation_endpoint = EXCLUDED.revocation_endpoint, iss_parameter_supported = EXCLUDED.iss_parameter_supported,
       client_id = EXCLUDED.client_id, redirect_uri = EXCLUDED.redirect_uri, resource = EXCLUDED.resource,
       scopes = EXCLUDED.scopes, return_to = EXCLUDED.return_to, finish_hash = EXCLUDED.finish_hash,
       pending_kind = EXCLUDED.pending_kind, pending_meta = EXCLUDED.pending_meta,
       created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at,
       verifier_key_id = EXCLUDED.verifier_key_id, verifier_wrapped_key = EXCLUDED.verifier_wrapped_key,
       verifier_key_nonce = EXCLUDED.verifier_key_nonce, verifier_ciphertext = EXCLUDED.verifier_ciphertext,
       verifier_nonce = EXCLUDED.verifier_nonce,
       pending_key_id = EXCLUDED.pending_key_id, pending_wrapped_key = EXCLUDED.pending_wrapped_key,
       pending_key_nonce = EXCLUDED.pending_key_nonce, pending_ciphertext = EXCLUDED.pending_ciphertext,
       pending_nonce = EXCLUDED.pending_nonce`,
		f.ID, f.Connection, nullable(f.StateHash), f.Issuer, f.AuthorizationEndpoint, f.TokenEndpoint,
		f.RevocationEndpoint, f.IssParameterSupported, f.ClientID, f.RedirectURI, f.Resource, scopes, f.ReturnTo,
		nullable(f.FinishHash), f.Pending.Kind, pendingMeta, nullTime(f.CreatedAt), f.ExpiresAt,
		nullable(v.KeyID), nullable(v.WrappedKey), nullable(v.KeyNonce), nullable(v.Ciphertext), nullable(v.Nonce),
		nullable(p.KeyID), nullable(p.WrappedKey), nullable(p.KeyNonce), nullable(p.Ciphertext), nullable(p.Nonce),
		x.v.at())
	if _, ok := violation(err, foreignKeyViolation); ok {
		return store.ErrNotFound
	}
	return err
}

func (x flows) Get(ctx context.Context, connectionID string) (store.Flow, error) {
	f, err := scanFlow(x.v.q.QueryRow(ctx, `SELECT `+flowCols+` FROM flows WHERE connection = $1`, connectionID))
	return f, one(err)
}

func (x flows) ByState(ctx context.Context, h []byte) (store.Flow, error) {
	if len(h) == 0 {
		return store.Flow{}, store.ErrNotFound
	}
	f, err := scanFlow(x.v.q.QueryRow(ctx, `SELECT `+flowCols+` FROM flows WHERE state_hash = $1`, h))
	return f, one(err)
}

func (x flows) Delete(ctx context.Context, connectionID string) error {
	_, err := x.v.q.Exec(ctx, `DELETE FROM flows WHERE connection = $1`, connectionID)
	return err
}

func (x flows) TakeExpired(ctx context.Context, now time.Time, limit int) ([]store.Flow, error) {
	if limit <= 0 {
		limit = store.SweepBatch
	}
	// The rows a sweeper takes are locked and skipped by another, so each
	// expired flow reaches one sweeper.
	rows, err := x.v.q.Query(ctx, `
DELETE FROM flows WHERE id IN (
  SELECT id FROM flows WHERE expires_at < $1 ORDER BY expires_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)
RETURNING `+flowCols, now, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanFlow)
}

// --- registrations --------------------------------------------------------

type registrations struct{ v *view }

func (x registrations) Put(ctx context.Context, r store.Registration) (store.Registration, error) {
	s := r.Secret
	if _, err := x.v.q.Exec(ctx, `
INSERT INTO registrations (issuer, redirect_uri, client_id, registered_at,
                           secret_key_id, secret_wrapped_key, secret_key_nonce, secret_ciphertext, secret_nonce)
VALUES ($1, $2, $3, coalesce($4::timestamptz, $10::timestamptz, now()), $5, $6, $7, $8, $9)
ON CONFLICT (issuer, redirect_uri) DO NOTHING`,
		r.Issuer, r.RedirectURI, r.ClientID, nullTime(r.RegisteredAt),
		nullable(s.KeyID), nullable(s.WrappedKey), nullable(s.KeyNonce), nullable(s.Ciphertext), nullable(s.Nonce),
		x.v.at()); err != nil {
		return store.Registration{}, err
	}
	// Of two replicas that register at once the first row is kept, and
	// both answer it.
	return x.Get(ctx, r.Issuer, r.RedirectURI)
}

func (x registrations) Get(ctx context.Context, issuer, redirectURI string) (store.Registration, error) {
	var r store.Registration
	s := &r.Secret
	err := x.v.q.QueryRow(ctx, `
SELECT issuer, redirect_uri, client_id, registered_at,
       secret_key_id, secret_wrapped_key, secret_key_nonce, secret_ciphertext, secret_nonce
  FROM registrations WHERE issuer = $1 AND redirect_uri = $2`, issuer, redirectURI).Scan(
		&r.Issuer, &r.RedirectURI, &r.ClientID, &r.RegisteredAt,
		&s.KeyID, &s.WrappedKey, &s.KeyNonce, &s.Ciphertext, &s.Nonce)
	r.RegisteredAt = r.RegisteredAt.UTC()
	return r, one(err)
}

func (x registrations) Delete(ctx context.Context, issuer, redirectURI string) error {
	_, err := x.v.q.Exec(ctx, `DELETE FROM registrations WHERE issuer = $1 AND redirect_uri = $2`, issuer, redirectURI)
	return err
}

// --- calls ----------------------------------------------------------------

type calls struct{ v *view }

const callCols = `id, connection, owner, connector, subject, session, at, duration_ms, method, tool, effect,
       coalesce(refs, 0), outcome, coalesce(status, 0), bytes_in, bytes_out`

func scanCall(row pgx.Row) (store.Call, error) {
	var c store.Call
	err := row.Scan(&c.ID, &c.Connection, &c.Owner, &c.Connector, &c.Subject, &c.Session, &c.At, &c.DurationMS,
		&c.Method, &c.Tool, &c.Effect, &c.Refs, &c.Outcome, &c.Status, &c.BytesIn, &c.BytesOut)
	c.At = c.At.UTC()
	return c, err
}

func (x calls) Insert(ctx context.Context, c store.Call) error {
	_, err := x.v.q.Exec(ctx, `
INSERT INTO calls (id, connection, owner, connector, subject, session, at, duration_ms, method, tool, effect,
                   refs, outcome, status, bytes_in, bytes_out)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		c.ID, c.Connection, c.Owner, c.Connector, c.Subject, c.Session, c.At, c.DurationMS, c.Method, c.Tool,
		c.Effect, nullInt(int64(c.Refs)), c.Outcome, nullInt(int64(c.Status)), c.BytesIn, c.BytesOut)
	return err
}

func (x calls) List(ctx context.Context, connectionID string, p store.Page) ([]store.Call, string, error) {
	size := p.Size()
	rows, err := x.v.q.Query(ctx, `SELECT `+callCols+` FROM calls
WHERE connection = $1 AND ($2 = '' OR id < $2) ORDER BY id DESC LIMIT $3`, connectionID, p.Cursor, size+1)
	if err != nil {
		return nil, "", err
	}
	out, err := collect(rows, scanCall)
	if err != nil {
		return nil, "", err
	}
	cs, next := page(out, func(c store.Call) string { return c.ID }, size)
	return cs, next, nil
}

func (x calls) Prune(ctx context.Context, before time.Time, limit int) (int, error) {
	tag, err := x.v.q.Exec(ctx, `
DELETE FROM calls WHERE id IN (
  SELECT id FROM calls WHERE at < $1 ORDER BY at LIMIT $2 FOR UPDATE SKIP LOCKED)`, before, pruneLimit(limit))
	return int(tag.RowsAffected()), err
}

// pruneLimit is the batch of one Prune, SweepBatch when it names none.
func pruneLimit(limit int) int {
	if limit <= 0 {
		return store.SweepBatch
	}
	return limit
}

// --- idempotency ----------------------------------------------------------

type idempotency struct{ v *view }

func (x idempotency) Put(ctx context.Context, k store.IdempotencyKey) error {
	_, err := x.v.q.Exec(ctx, `
INSERT INTO idempotency_keys (subject, key, route, status, object, created_at)
VALUES ($1, $2, $3, $4, $5, coalesce($6::timestamptz, $7::timestamptz, now()))`,
		k.Subject, k.Key, k.Route, k.Status, k.Object, nullTime(k.CreatedAt), x.v.at())
	if _, ok := violation(err, uniqueViolation); ok {
		return store.ErrKeyTaken
	}
	return err
}

func (x idempotency) Get(ctx context.Context, subject, key string) (store.IdempotencyKey, error) {
	var k store.IdempotencyKey
	err := x.v.q.QueryRow(ctx, `
SELECT subject, key, route, status, object, created_at FROM idempotency_keys WHERE subject = $1 AND key = $2`,
		subject, key).Scan(&k.Subject, &k.Key, &k.Route, &k.Status, &k.Object, &k.CreatedAt)
	k.CreatedAt = k.CreatedAt.UTC()
	return k, one(err)
}

func (x idempotency) Prune(ctx context.Context, before time.Time, limit int) (int, error) {
	tag, err := x.v.q.Exec(ctx, `
DELETE FROM idempotency_keys WHERE (subject, key) IN (
  SELECT subject, key FROM idempotency_keys WHERE created_at < $1 ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED)`,
		before, pruneLimit(limit))
	return int(tag.RowsAffected()), err
}
