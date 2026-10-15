// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/pons/internal/store"
)

// jsonText is a value as the text of a json column. A nil list is an empty
// one and nil raw JSON the empty document.
func jsonText(v any, empty string) (string, error) {
	switch x := v.(type) {
	case []string:
		if x == nil {
			return empty, nil
		}
	case json.RawMessage:
		if len(x) == 0 {
			return empty, nil
		}
		if !json.Valid(x) {
			return "", errors.New("store: a json column holds a value that is not JSON")
		}
		return string(x), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: encoding a json column: %w", err)
	}
	return string(b), nil
}

// list reads a json array of strings.
func list(text string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, fmt.Errorf("store: reading a json column: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// raw reads a json document, nil for the empty one.
func raw(text string) json.RawMessage {
	if text == "" || text == "{}" {
		return nil
	}
	return json.RawMessage(text)
}

// --- connectors -----------------------------------------------------------

type connectors struct{ v *view }

const connectorCols = `id, owner, name, title, description, icon, kind, url, hosts::text, auth::text, tools::text,
       sign_in::text, vouched, disabled,
       client_secret_key_id, client_secret_wrapped_key, client_secret_key_nonce, client_secret_ciphertext, client_secret_nonce,
       created_at`

func scanConnector(row pgx.Row) (store.Connector, error) {
	var c store.Connector
	var hosts, auth, tools, signIn string
	s := &c.ClientSecret
	if err := row.Scan(&c.ID, &c.Owner, &c.Name, &c.Title, &c.Description, &c.Icon, &c.Kind, &c.URL,
		&hosts, &auth, &tools, &signIn, &c.Vouched, &c.Disabled,
		&s.KeyID, &s.WrappedKey, &s.KeyNonce, &s.Ciphertext, &s.Nonce, &c.CreatedAt); err != nil {
		return store.Connector{}, err
	}
	h, err := list(hosts)
	if err != nil {
		return store.Connector{}, err
	}
	c.Hosts, c.Auth, c.Tools, c.SignIn, c.CreatedAt = h, raw(auth), raw(tools), raw(signIn), c.CreatedAt.UTC()
	return c, nil
}

// documents are a connector's json columns as text.
func documents(c store.Connector) (hosts, auth, tools, signIn string, err error) {
	if hosts, err = jsonText(c.Hosts, "[]"); err != nil {
		return
	}
	if auth, err = jsonText(c.Auth, "{}"); err != nil {
		return
	}
	if tools, err = jsonText(c.Tools, "{}"); err != nil {
		return
	}
	signIn, err = jsonText(c.SignIn, "{}")
	return
}

func (x connectors) Create(ctx context.Context, c store.Connector, max int) error {
	hosts, auth, tools, signIn, err := documents(c)
	if err != nil {
		return err
	}
	s := c.ClientSecret
	insert := func(q querier) error {
		_, err := q.Exec(ctx, `
INSERT INTO connectors (id, owner, name, title, description, icon, kind, url, hosts, auth, tools, sign_in, vouched, disabled,
                        client_secret_key_id, client_secret_wrapped_key, client_secret_key_nonce, client_secret_ciphertext,
                        client_secret_nonce, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14,
        $15, $16, $17, $18, $19, coalesce($20::timestamptz, $21::timestamptz, now()))`,
			c.ID, c.Owner, c.Name, c.Title, c.Description, c.Icon, c.Kind, c.URL, hosts, auth, tools, signIn, c.Vouched, c.Disabled,
			nullable(s.KeyID), nullable(s.WrappedKey), nullable(s.KeyNonce), nullable(s.Ciphertext), nullable(s.Nonce),
			nullTime(c.CreatedAt), x.v.at())
		if name, ok := violation(err, uniqueViolation); ok && name == "connectors_owner_name_key" {
			return store.ErrNameTaken
		}
		return err
	}
	if max <= 0 {
		return insert(x.v.q)
	}
	// The count and the insert are made under one lock on the owner, so
	// two adds at one remaining place yield one connector. The key is
	// apart from a connection's, so an add and a connect of one owner do
	// not wait on each other.
	return x.v.atomic(ctx, func(q querier) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 1))`, c.Owner); err != nil {
			return err
		}
		var held int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM connectors WHERE owner = $1`, c.Owner).Scan(&held); err != nil {
			return err
		}
		if held >= max {
			return store.ErrLimitReached
		}
		return insert(q)
	})
}

func (x connectors) Update(ctx context.Context, c store.Connector) error {
	auth, err := jsonText(c.Auth, "{}")
	if err != nil {
		return err
	}
	tools, err := jsonText(c.Tools, "{}")
	if err != nil {
		return err
	}
	s := c.ClientSecret
	tag, err := x.v.q.Exec(ctx, `
UPDATE connectors SET title = $2, description = $3, icon = $4, auth = $5::jsonb, tools = $6::jsonb, disabled = $7,
       client_secret_key_id = $8, client_secret_wrapped_key = $9, client_secret_key_nonce = $10,
       client_secret_ciphertext = $11, client_secret_nonce = $12
 WHERE id = $1`, c.ID, c.Title, c.Description, c.Icon, auth, tools, c.Disabled,
		nullable(s.KeyID), nullable(s.WrappedKey), nullable(s.KeyNonce), nullable(s.Ciphertext), nullable(s.Nonce))
	return affected(tag.RowsAffected(), err)
}

func (x connectors) Get(ctx context.Context, id string) (store.Connector, error) {
	c, err := scanConnector(x.v.q.QueryRow(ctx, `SELECT `+connectorCols+` FROM connectors WHERE id = $1`, id))
	return c, one(err)
}

func (x connectors) List(ctx context.Context, owners []string, p store.Page) ([]store.Connector, string, error) {
	if len(owners) == 0 {
		return nil, "", nil
	}
	size := p.Size()
	rows, err := x.v.q.Query(ctx, `SELECT `+connectorCols+` FROM connectors
WHERE owner = ANY($1) AND ($2 = '' OR id < $2) ORDER BY id DESC LIMIT $3`, owners, p.Cursor, size+1)
	if err != nil {
		return nil, "", err
	}
	out, err := collect(rows, scanConnector)
	if err != nil {
		return nil, "", err
	}
	cs, next := page(out, func(c store.Connector) string { return c.ID }, size)
	return cs, next, nil
}

func (x connectors) Delete(ctx context.Context, id string) error {
	return x.v.atomic(ctx, func(q querier) error {
		var used bool
		err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM connectors WHERE id = $1),
       EXISTS (SELECT 1 FROM connections WHERE connector = $1)`, id).Scan(new(bool), &used)
		if err != nil {
			return err
		}
		if used {
			return store.ErrInUse
		}
		tag, err := q.Exec(ctx, `DELETE FROM connectors WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

// collect reads every row with scan.
func collect[T any](rows pgx.Rows, scan func(pgx.Row) (T, error)) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// --- connections ----------------------------------------------------------

type connections struct{ v *view }

const connectionCols = `id, owner, name, connector, kind, auth, state, reason, account, scopes::text,
       created_by, created_at, updated_at, last_used_at, expires_at`

func scanConnection(row pgx.Row) (store.Connection, error) {
	var c store.Connection
	var scopes string
	var lastUsed, expires *time.Time
	if err := row.Scan(&c.ID, &c.Owner, &c.Name, &c.Connector, &c.Kind, &c.Auth, &c.State, &c.Reason, &c.Account,
		&scopes, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &lastUsed, &expires); err != nil {
		return store.Connection{}, err
	}
	s, err := list(scopes)
	if err != nil {
		return store.Connection{}, err
	}
	c.Scopes, c.LastUsedAt, c.ExpiresAt = s, timeOf(lastUsed), timeOf(expires)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	return c, nil
}

func (x connections) Create(ctx context.Context, c store.Connection, max int) error {
	if c.State != store.StatePending && c.State != store.StateConnected {
		return store.ErrIllegalMove
	}
	scopes, err := jsonText(c.Scopes, "[]")
	if err != nil {
		return err
	}
	insert := func(q querier) error {
		_, err := q.Exec(ctx, `
INSERT INTO connections (id, owner, name, connector, kind, auth, state, reason, account, scopes, created_by,
                         created_at, updated_at, last_used_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11,
        coalesce($12::timestamptz, $14::timestamptz, now()), coalesce($14::timestamptz, now()), $13::timestamptz, $15::timestamptz)`,
			c.ID, c.Owner, c.Name, c.Connector, c.Kind, c.Auth, string(c.State), c.Reason, c.Account, scopes, c.CreatedBy,
			nullTime(c.CreatedAt), nullTime(c.LastUsedAt), x.v.at(), nullTime(c.ExpiresAt))
		if name, ok := violation(err, uniqueViolation); ok && name == "connections_owner_name_key" {
			return store.ErrNameTaken
		}
		return err
	}
	if max <= 0 {
		return insert(x.v.q)
	}
	// The count and the insert are made under one lock on the owner, so
	// two creates at one remaining place yield one connection.
	return x.v.atomic(ctx, func(q querier) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, c.Owner); err != nil {
			return err
		}
		var held int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM connections WHERE owner = $1`, c.Owner).Scan(&held); err != nil {
			return err
		}
		if held >= max {
			return store.ErrLimitReached
		}
		return insert(q)
	})
}

func (x connections) Get(ctx context.Context, id string) (store.Connection, error) {
	c, err := scanConnection(x.v.q.QueryRow(ctx, `SELECT `+connectionCols+` FROM connections WHERE id = $1`, id))
	return c, one(err)
}

func (x connections) List(ctx context.Context, f store.Filter, p store.Page) ([]store.Connection, string, error) {
	if len(f.Owners) == 0 {
		return nil, "", nil
	}
	size := p.Size()
	rows, err := x.v.q.Query(ctx, `SELECT `+connectionCols+` FROM connections
WHERE owner = ANY($1) AND ($2 = '' OR connector = $2) AND ($3 = '' OR state = $3) AND ($4 = '' OR id < $4)
ORDER BY id DESC LIMIT $5`, f.Owners, f.Connector, string(f.State), p.Cursor, size+1)
	if err != nil {
		return nil, "", err
	}
	out, err := collect(rows, scanConnection)
	if err != nil {
		return nil, "", err
	}
	cs, next := page(out, func(c store.Connection) string { return c.ID }, size)
	return cs, next, nil
}

// affected maps a write that matched no row to store.ErrNotFound.
func affected(n int64, err error) error {
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (x connections) Rename(ctx context.Context, id, name string) error {
	tag, err := x.v.q.Exec(ctx, `UPDATE connections SET name = $2, updated_at = coalesce($3::timestamptz, now()) WHERE id = $1`,
		id, name, x.v.at())
	if n, ok := violation(err, uniqueViolation); ok && n == "connections_owner_name_key" {
		return store.ErrNameTaken
	}
	return affected(tag.RowsAffected(), err)
}

func (x connections) Move(ctx context.Context, id string, from, to store.State, reason string) error {
	if !store.Legal(from, to) {
		return store.ErrIllegalMove
	}
	// The reason follows store.NextReason: cleared, set to the given one,
	// or kept, decided here so the statement reads nothing first.
	clearReason := to == store.StateConnected
	setReason := !clearReason && store.NextReason(from, to, "\x00", reason) != "\x00"
	tag, err := x.v.q.Exec(ctx, `
UPDATE connections SET state = $3,
       reason = CASE WHEN $4::boolean THEN '' WHEN $5::boolean THEN $6 ELSE reason END,
       updated_at = coalesce($7::timestamptz, now())
 WHERE id = $1 AND state = $2`, id, string(from), string(to), clearReason, setReason, reason, x.v.at())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := x.v.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM connections WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return store.ErrStateMoved
}

func (x connections) Describe(ctx context.Context, id string, a store.Account) error {
	scopes, err := jsonText(a.Scopes, "[]")
	if err != nil {
		return err
	}
	tag, err := x.v.q.Exec(ctx, `
UPDATE connections SET account = $2, scopes = $3::jsonb, expires_at = $4::timestamptz,
       updated_at = coalesce($5::timestamptz, now())
 WHERE id = $1`, id, a.Account, scopes, nullTime(a.ExpiresAt), x.v.at())
	return affected(tag.RowsAffected(), err)
}

func (x connections) Touch(ctx context.Context, id string, at time.Time) error {
	_, err := x.v.q.Exec(ctx, `
UPDATE connections SET last_used_at = $2
 WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $2::timestamptz - $3::bigint * interval '1 microsecond')`,
		id, at, store.TouchInterval.Microseconds())
	return err
}

func (x connections) Delete(ctx context.Context, id string) error {
	// The credential and the flow go with the row, by their cascading
	// foreign keys, in this one statement.
	tag, err := x.v.q.Exec(ctx, `DELETE FROM connections WHERE id = $1`, id)
	return affected(tag.RowsAffected(), err)
}

func (x connections) CountByState(ctx context.Context) (map[store.State]int64, error) {
	rows, err := x.v.q.Query(ctx, `SELECT state, count(*) FROM connections GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[store.State]int64{}
	for rows.Next() {
		var state string
		var n int64
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[store.State(state)] = n
	}
	return out, rows.Err()
}

func (x connections) InUse(ctx context.Context, connector string) (bool, error) {
	var used bool
	err := x.v.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM connections WHERE connector = $1)`, connector).Scan(&used)
	return used, err
}

func (x connections) CountByConnector(ctx context.Context, refs []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(refs) == 0 {
		return out, nil
	}
	rows, err := x.v.q.Query(ctx, `SELECT connector, count(*) FROM connections WHERE connector = ANY($1) GROUP BY connector`, refs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ref string
		var n int64
		if err := rows.Scan(&ref, &n); err != nil {
			return nil, err
		}
		out[ref] = n
	}
	return out, rows.Err()
}

// --- credentials ----------------------------------------------------------

type credentials struct{ v *view }

func (x credentials) Put(ctx context.Context, connectionID string, c store.SealedCredential) (int64, error) {
	meta, err := jsonText(c.Meta, "{}")
	if err != nil {
		return 0, err
	}
	var version int64
	err = x.v.q.QueryRow(ctx, `
INSERT INTO credentials AS c (connection, kind, meta, key_id, wrapped_key, key_nonce, ciphertext, nonce,
                              version, refresh_until, updated_at)
VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, 1, NULL, coalesce($9::timestamptz, now()))
ON CONFLICT (connection) DO UPDATE SET kind = EXCLUDED.kind, meta = EXCLUDED.meta,
       key_id = EXCLUDED.key_id, wrapped_key = EXCLUDED.wrapped_key, key_nonce = EXCLUDED.key_nonce,
       ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce,
       version = c.version + 1, refresh_until = NULL, updated_at = EXCLUDED.updated_at
RETURNING version`, connectionID, c.Kind, meta, c.Sealed.KeyID, c.Sealed.WrappedKey, c.Sealed.KeyNonce,
		c.Sealed.Ciphertext, c.Sealed.Nonce, x.v.at()).Scan(&version)
	if _, ok := violation(err, foreignKeyViolation); ok {
		return 0, store.ErrNotFound
	}
	return version, err
}

func (x credentials) Get(ctx context.Context, connectionID string) (store.SealedCredential, int64, error) {
	var c store.SealedCredential
	var meta string
	var version int64
	err := x.v.q.QueryRow(ctx, `
SELECT kind, meta::text, key_id, wrapped_key, key_nonce, ciphertext, nonce, version
  FROM credentials WHERE connection = $1`, connectionID).Scan(&c.Kind, &meta, &c.Sealed.KeyID,
		&c.Sealed.WrappedKey, &c.Sealed.KeyNonce, &c.Sealed.Ciphertext, &c.Sealed.Nonce, &version)
	if err != nil {
		return store.SealedCredential{}, 0, one(err)
	}
	c.Meta = raw(meta)
	return c, version, nil
}

// version reads a credential's version: store.ErrNotFound when it has none.
func (x credentials) version(ctx context.Context, connectionID string) (int64, error) {
	var v int64
	err := x.v.q.QueryRow(ctx, `SELECT version FROM credentials WHERE connection = $1`, connectionID).Scan(&v)
	return v, one(err)
}

func (x credentials) ClaimRefresh(ctx context.Context, connectionID string, lease time.Duration) (bool, int64, error) {
	var version int64
	err := x.v.q.QueryRow(ctx, `
UPDATE credentials SET refresh_until = coalesce($3::timestamptz, now()) + $2::bigint * interval '1 microsecond'
 WHERE connection = $1 AND (refresh_until IS NULL OR refresh_until <= coalesce($3::timestamptz, now()))
RETURNING version`, connectionID, lease.Microseconds(), x.v.at()).Scan(&version)
	if err == nil {
		return true, version, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, 0, err
	}
	version, err = x.version(ctx, connectionID)
	return false, version, err
}

func (x credentials) CompleteRefresh(ctx context.Context, connectionID string, fromVersion int64, sealed store.SealedCredential) error {
	meta, err := jsonText(sealed.Meta, "{}")
	if err != nil {
		return err
	}
	tag, err := x.v.q.Exec(ctx, `
UPDATE credentials SET kind = $3, meta = $4::jsonb, key_id = $5, wrapped_key = $6, key_nonce = $7,
       ciphertext = $8, nonce = $9, version = version + 1, refresh_until = NULL,
       updated_at = coalesce($10::timestamptz, now())
 WHERE connection = $1 AND version = $2`, connectionID, fromVersion, sealed.Kind, meta, sealed.Sealed.KeyID,
		sealed.Sealed.WrappedKey, sealed.Sealed.KeyNonce, sealed.Sealed.Ciphertext, sealed.Sealed.Nonce, x.v.at())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := x.version(ctx, connectionID); err != nil {
		return err
	}
	return store.ErrVersionMoved
}

func (x credentials) ReleaseRefresh(ctx context.Context, connectionID string) error {
	tag, err := x.v.q.Exec(ctx, `UPDATE credentials SET refresh_until = NULL WHERE connection = $1`, connectionID)
	return affected(tag.RowsAffected(), err)
}

func (x credentials) GrantHolders(ctx context.Context, g store.Grant) (int64, error) {
	if g.Account == "" {
		return 0, nil
	}
	// One statement reads one snapshot, so a confirm's transaction, which
	// writes the credential and deletes the flow, is seen whole or not at
	// all. A member the meta leaves out is the empty string.
	var n int64
	err := x.v.q.QueryRow(ctx, `
SELECT (SELECT count(*) FROM credentials
         WHERE kind = $1 AND coalesce(meta->>'issuer', '') = $2
           AND coalesce(meta->>'client_id', '') = $3 AND meta->>'account' = $4)
     + (SELECT count(*) FROM flows
         WHERE pending_kind = $1 AND coalesce(pending_meta->>'issuer', '') = $2
           AND coalesce(pending_meta->>'client_id', '') = $3 AND pending_meta->>'account' = $4)`,
		store.KindOAuth, g.Issuer, g.ClientID, g.Account).Scan(&n)
	return n, err
}
