// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package memory is the store that runs when no database is configured,
// for development and tests (specs/005-store-and-sealing.md): maps under
// one mutex, which is the transaction. Nothing survives the process. It
// runs the same edges, leases, versions and sealed values as Postgres, on a
// clock a test can move.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"latere.ai/x/pons/internal/store"
)

// Options configures the store.
type Options struct {
	// Now is the store's clock: created and updated times and refresh
	// leases are judged on it. Nil is time.Now.
	Now func() time.Time
}

// Store is the memory store.
type Store struct {
	mu   sync.Mutex
	now  func() time.Time
	data *data
}

// data is every table.
type data struct {
	connectors    map[string]store.Connector
	connections   map[string]store.Connection
	credentials   map[string]credential
	flows         map[string]store.Flow // by connection
	registrations map[[2]string]store.Registration
	calls         map[string]store.Call
	idempotency   map[[2]string]store.IdempotencyKey
}

// credential is a credentials row.
type credential struct {
	sealed       store.SealedCredential
	version      int64
	refreshUntil time.Time // zero when no lease is held
	updatedAt    time.Time
}

var _ store.Store = (*Store)(nil)

// New makes an empty store.
func New(o Options) *Store {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, data: &data{
		connectors:    map[string]store.Connector{},
		connections:   map[string]store.Connection{},
		credentials:   map[string]credential{},
		flows:         map[string]store.Flow{},
		registrations: map[[2]string]store.Registration{},
		calls:         map[string]store.Call{},
		idempotency:   map[[2]string]store.IdempotencyKey{},
	}}
}

// Tx runs fn under the mutex. Every write records how to undo it, so an
// error fn returns leaves nothing behind.
func (s *Store) Tx(ctx context.Context, fn func(store.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := &view{d: s.data, now: s.now}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(v); err != nil {
		v.rollback()
		return err
	}
	return nil
}

// Ready answers that the store can serve.
func (s *Store) Ready(context.Context) error { return nil }

// Close releases nothing: the maps go with the process.
func (s *Store) Close() error { return nil }

// one runs a single call as its own transaction.
func (s *Store) one(ctx context.Context, fn func(*view) error) error {
	return s.Tx(ctx, func(tx store.Tx) error {
		v, ok := tx.(*view)
		if !ok {
			return errors.New("memory: a transaction that is not the memory store's")
		}
		return fn(v)
	})
}

func (s *Store) Connectors() store.Connectors       { return connectors{s: s} }
func (s *Store) Connections() store.Connections     { return connections{s: s} }
func (s *Store) Credentials() store.Credentials     { return credentials{s: s} }
func (s *Store) Flows() store.Flows                 { return flows{s: s} }
func (s *Store) Registrations() store.Registrations { return registrations{s: s} }
func (s *Store) Calls() store.Calls                 { return calls{s: s} }
func (s *Store) Idempotency() store.Idempotency     { return idempotency{s: s} }
func (s *Store) Rotation() store.Rotation           { return rotation{s: s} }

// Dump writes every value the store holds, every string and every byte
// slice as it is, for a test that searches what is kept at rest.
func (s *Store) Dump() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b bytes.Buffer
	dump(&b, reflect.ValueOf(*s.data))
	return b.Bytes()
}

// dump walks a value and writes its strings and bytes.
func dump(b *bytes.Buffer, v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		b.WriteString(v.String())
		b.WriteByte('\n')
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b.Write(v.Bytes())
			b.WriteByte('\n')
			return
		}
		for i := range v.Len() {
			dump(b, v.Index(i))
		}
	case reflect.Array:
		for i := range v.Len() {
			dump(b, v.Index(i))
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			dump(b, iter.Key())
			dump(b, iter.Value())
		}
	case reflect.Struct:
		for _, field := range v.Fields() {
			dump(b, field)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			dump(b, v.Elem())
		}
	}
}

// view is the tables inside one transaction. It holds the mutex the
// transaction took, so its methods lock nothing.
type view struct {
	d    *data
	now  func() time.Time
	undo []func()
}

func (v *view) rollback() {
	for _, undo := range slices.Backward(v.undo) {
		undo()
	}
	v.undo = nil
}

// put writes one row and records how to undo the write.
func put[K comparable, V any](v *view, m map[K]V, k K, val V) {
	old, existed := m[k]
	v.undo = append(v.undo, func() {
		if existed {
			m[k] = old
		} else {
			delete(m, k)
		}
	})
	m[k] = val
}

// del removes one row and records how to undo the removal.
func del[K comparable, V any](v *view, m map[K]V, k K) {
	old, existed := m[k]
	if !existed {
		return
	}
	v.undo = append(v.undo, func() { m[k] = old })
	delete(m, k)
}

func (v *view) Connectors() store.Connectors       { return viewConnectors{v} }
func (v *view) Connections() store.Connections     { return viewConnections{v} }
func (v *view) Credentials() store.Credentials     { return viewCredentials{v} }
func (v *view) Flows() store.Flows                 { return viewFlows{v} }
func (v *view) Registrations() store.Registrations { return viewRegistrations{v} }
func (v *view) Calls() store.Calls                 { return viewCalls{v} }
func (v *view) Idempotency() store.Idempotency     { return viewIdempotency{v} }
func (v *view) Rotation() store.Rotation           { return viewRotation{v} }

// page cuts a list sorted newest first by id to one page after the cursor.
func page[T any](rows []T, idOf func(T) string, p store.Page) ([]T, string) {
	if p.Cursor != "" {
		rows = slices.DeleteFunc(rows, func(row T) bool { return idOf(row) >= p.Cursor })
	}
	slices.SortFunc(rows, func(a, b T) int { return cmp.Compare(idOf(b), idOf(a)) })
	size := p.Size()
	if len(rows) > size {
		return rows[:size], idOf(rows[size-1])
	}
	return rows, ""
}

// --- connectors -----------------------------------------------------------

func cloneConnector(c store.Connector) store.Connector {
	c.Hosts = slices.Clone(c.Hosts)
	c.Auth = bytes.Clone(c.Auth)
	c.Tools = bytes.Clone(c.Tools)
	c.SignIn = bytes.Clone(c.SignIn)
	c.ClientSecret = cloneSealed(c.ClientSecret)
	return c
}

type viewConnectors struct{ v *view }

func (x viewConnectors) Create(_ context.Context, c store.Connector, max int) error {
	v := x.v
	if _, ok := v.d.connectors[c.ID]; ok {
		return fmt.Errorf("store: the connector id %s is taken", c.ID)
	}
	// The cap is counted before the name is compared, as Postgres counts
	// before its insert meets the unique key.
	held, taken := 0, false
	for _, other := range v.d.connectors {
		if other.Owner == c.Owner {
			held++
			taken = taken || other.Name == c.Name
		}
	}
	switch {
	case max > 0 && held >= max:
		return store.ErrLimitReached
	case taken:
		return store.ErrNameTaken
	}
	if err := checkJSON(c.Auth, c.Tools, c.SignIn); err != nil {
		return err
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = v.now()
	}
	put(v, v.d.connectors, c.ID, cloneConnector(c))
	return nil
}

func (x viewConnectors) Update(_ context.Context, c store.Connector) error {
	v := x.v
	row, ok := v.d.connectors[c.ID]
	if !ok {
		return store.ErrNotFound
	}
	if err := checkJSON(c.Auth, c.Tools); err != nil {
		return err
	}
	row.Title, row.Description, row.Icon = c.Title, c.Description, c.Icon
	row.Auth, row.Tools, row.Disabled, row.ClientSecret = c.Auth, c.Tools, c.Disabled, c.ClientSecret
	put(v, v.d.connectors, c.ID, cloneConnector(row))
	return nil
}

func (x viewConnectors) Get(_ context.Context, id string) (store.Connector, error) {
	c, ok := x.v.d.connectors[id]
	if !ok {
		return store.Connector{}, store.ErrNotFound
	}
	return cloneConnector(c), nil
}

func (x viewConnectors) List(_ context.Context, owners []string, p store.Page) ([]store.Connector, string, error) {
	var rows []store.Connector
	for _, c := range x.v.d.connectors {
		if slices.Contains(owners, c.Owner) {
			rows = append(rows, cloneConnector(c))
		}
	}
	out, next := page(rows, func(c store.Connector) string { return c.ID }, p)
	return out, next, nil
}

func (x viewConnectors) Delete(_ context.Context, id string) error {
	v := x.v
	if _, ok := v.d.connectors[id]; !ok {
		return store.ErrNotFound
	}
	for _, c := range v.d.connections {
		if c.Connector == id {
			return store.ErrInUse
		}
	}
	del(v, v.d.connectors, id)
	return nil
}

// checkJSON refuses a json column that is not JSON, as Postgres does.
func checkJSON(docs ...json.RawMessage) error {
	for _, d := range docs {
		if len(d) > 0 && !json.Valid(d) {
			return errors.New("store: a json column holds a value that is not JSON")
		}
	}
	return nil
}

// --- connections ----------------------------------------------------------

type viewConnections struct{ v *view }

func cloneConnection(c store.Connection) store.Connection {
	c.Scopes = slices.Clone(c.Scopes)
	return c
}

func (x viewConnections) Create(_ context.Context, c store.Connection, max int) error {
	v := x.v
	if c.State != store.StatePending && c.State != store.StateConnected {
		return store.ErrIllegalMove
	}
	if _, ok := v.d.connections[c.ID]; ok {
		return fmt.Errorf("store: the connection id %s is taken", c.ID)
	}
	if max > 0 {
		held := 0
		for _, other := range v.d.connections {
			if other.Owner == c.Owner {
				held++
			}
		}
		if held >= max {
			return store.ErrLimitReached
		}
	}
	for _, other := range v.d.connections {
		if other.Owner == c.Owner && other.Name == c.Name {
			return store.ErrNameTaken
		}
	}
	now := v.now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	put(v, v.d.connections, c.ID, cloneConnection(c))
	return nil
}

func (x viewConnections) Get(_ context.Context, id string) (store.Connection, error) {
	c, ok := x.v.d.connections[id]
	if !ok {
		return store.Connection{}, store.ErrNotFound
	}
	return cloneConnection(c), nil
}

func (x viewConnections) List(_ context.Context, f store.Filter, p store.Page) ([]store.Connection, string, error) {
	var rows []store.Connection
	for _, c := range x.v.d.connections {
		if !slices.Contains(f.Owners, c.Owner) ||
			(f.Connector != "" && c.Connector != f.Connector) || (f.State != "" && c.State != f.State) {
			continue
		}
		rows = append(rows, cloneConnection(c))
	}
	out, next := page(rows, func(c store.Connection) string { return c.ID }, p)
	return out, next, nil
}

// change writes one connection after fn changed it, stamping updated_at.
func (x viewConnections) change(id string, fn func(*store.Connection) error) error {
	v := x.v
	c, ok := v.d.connections[id]
	if !ok {
		return store.ErrNotFound
	}
	c = cloneConnection(c)
	if err := fn(&c); err != nil {
		return err
	}
	c.UpdatedAt = v.now()
	put(v, v.d.connections, id, c)
	return nil
}

func (x viewConnections) Rename(_ context.Context, id, name string) error {
	return x.change(id, func(c *store.Connection) error {
		for otherID, other := range x.v.d.connections {
			if otherID != id && other.Owner == c.Owner && other.Name == name {
				return store.ErrNameTaken
			}
		}
		c.Name = name
		return nil
	})
}

func (x viewConnections) Move(_ context.Context, id string, from, to store.State, reason string) error {
	if !store.Legal(from, to) {
		return store.ErrIllegalMove
	}
	return x.change(id, func(c *store.Connection) error {
		if c.State != from {
			return store.ErrStateMoved
		}
		c.State = to
		c.Reason = store.NextReason(from, to, c.Reason, reason)
		return nil
	})
}

func (x viewConnections) Describe(_ context.Context, id string, a store.Account) error {
	return x.change(id, func(c *store.Connection) error {
		c.Account, c.Scopes, c.ExpiresAt = a.Account, slices.Clone(a.Scopes), a.ExpiresAt
		return nil
	})
}

func (x viewConnections) Touch(_ context.Context, id string, at time.Time) error {
	v := x.v
	c, ok := v.d.connections[id]
	if !ok {
		// Touch reads nothing first, so a connection that is gone is no
		// error, as the one conditional statement of Postgres is none.
		return nil
	}
	if !c.LastUsedAt.IsZero() && !c.LastUsedAt.Before(at.Add(-store.TouchInterval)) {
		return nil
	}
	c = cloneConnection(c)
	c.LastUsedAt = at
	put(v, v.d.connections, id, c)
	return nil
}

func (x viewConnections) Delete(_ context.Context, id string) error {
	v := x.v
	if _, ok := v.d.connections[id]; !ok {
		return store.ErrNotFound
	}
	// The credential and the flow go with the row, as the cascading
	// foreign keys take them in Postgres.
	del(v, v.d.credentials, id)
	del(v, v.d.flows, id)
	del(v, v.d.connections, id)
	return nil
}

func (x viewConnections) CountByState(context.Context) (map[store.State]int64, error) {
	out := map[store.State]int64{}
	for _, c := range x.v.d.connections {
		out[c.State]++
	}
	return out, nil
}

func (x viewConnections) CountByConnector(_ context.Context, refs []string) (map[string]int64, error) {
	out := map[string]int64{}
	for _, c := range x.v.d.connections {
		if slices.Contains(refs, c.Connector) {
			out[c.Connector]++
		}
	}
	return out, nil
}

func (x viewConnections) InUse(_ context.Context, connector string) (bool, error) {
	for _, c := range x.v.d.connections {
		if c.Connector == connector {
			return true, nil
		}
	}
	return false, nil
}

// --- credentials ----------------------------------------------------------

type viewCredentials struct{ v *view }

func cloneSealed(s store.Sealed) store.Sealed {
	return store.Sealed{
		KeyID: bytes.Clone(s.KeyID), WrappedKey: bytes.Clone(s.WrappedKey), KeyNonce: bytes.Clone(s.KeyNonce),
		Ciphertext: bytes.Clone(s.Ciphertext), Nonce: bytes.Clone(s.Nonce),
	}
}

func cloneCredential(c store.SealedCredential) store.SealedCredential {
	return store.SealedCredential{Kind: c.Kind, Meta: bytes.Clone(c.Meta), Sealed: cloneSealed(c.Sealed)}
}

func (x viewCredentials) Put(_ context.Context, connectionID string, c store.SealedCredential) (int64, error) {
	v := x.v
	if _, ok := v.d.connections[connectionID]; !ok {
		return 0, store.ErrNotFound
	}
	if err := checkJSON(c.Meta); err != nil {
		return 0, err
	}
	version := v.d.credentials[connectionID].version + 1
	put(v, v.d.credentials, connectionID, credential{sealed: cloneCredential(c), version: version, updatedAt: v.now()})
	return version, nil
}

func (x viewCredentials) Get(_ context.Context, connectionID string) (store.SealedCredential, int64, error) {
	row, ok := x.v.d.credentials[connectionID]
	if !ok {
		return store.SealedCredential{}, 0, store.ErrNotFound
	}
	return cloneCredential(row.sealed), row.version, nil
}

func (x viewCredentials) ClaimRefresh(_ context.Context, connectionID string, lease time.Duration) (bool, int64, error) {
	v := x.v
	row, ok := v.d.credentials[connectionID]
	if !ok {
		return false, 0, store.ErrNotFound
	}
	now := v.now()
	if !row.refreshUntil.IsZero() && row.refreshUntil.After(now) {
		return false, row.version, nil
	}
	row.refreshUntil = now.Add(lease)
	put(v, v.d.credentials, connectionID, row)
	return true, row.version, nil
}

func (x viewCredentials) CompleteRefresh(_ context.Context, connectionID string, fromVersion int64, sealed store.SealedCredential) error {
	v := x.v
	row, ok := v.d.credentials[connectionID]
	if !ok {
		return store.ErrNotFound
	}
	if row.version != fromVersion {
		return store.ErrVersionMoved
	}
	if err := checkJSON(sealed.Meta); err != nil {
		return err
	}
	put(v, v.d.credentials, connectionID, credential{
		sealed: cloneCredential(sealed), version: row.version + 1, updatedAt: v.now(),
	})
	return nil
}

func (x viewCredentials) ReleaseRefresh(_ context.Context, connectionID string) error {
	v := x.v
	row, ok := v.d.credentials[connectionID]
	if !ok {
		return store.ErrNotFound
	}
	row.refreshUntil = time.Time{}
	put(v, v.d.credentials, connectionID, row)
	return nil
}

func (x viewCredentials) GrantHolders(_ context.Context, g store.Grant) (int64, error) {
	if g.Account == "" {
		return 0, nil
	}
	holds := func(c store.SealedCredential) (bool, error) {
		if c.Kind != store.KindOAuth {
			return false, nil
		}
		m, err := store.DecodeMeta(c.Meta)
		if err != nil {
			return false, err
		}
		return m.Grant() == g, nil
	}
	var n int64
	for _, row := range x.v.d.credentials {
		held, err := holds(row.sealed)
		if err != nil {
			return 0, err
		}
		if held {
			n++
		}
	}
	for _, f := range x.v.d.flows {
		held, err := holds(f.Pending)
		if err != nil {
			return 0, err
		}
		if held {
			n++
		}
	}
	return n, nil
}

// --- flows ----------------------------------------------------------------

type viewFlows struct{ v *view }

func cloneFlow(f store.Flow) store.Flow {
	f.StateHash = bytes.Clone(f.StateHash)
	f.FinishHash = bytes.Clone(f.FinishHash)
	f.Scopes = slices.Clone(f.Scopes)
	f.Verifier = cloneSealed(f.Verifier)
	f.Pending = cloneCredential(f.Pending)
	return f
}

func (x viewFlows) Put(_ context.Context, f store.Flow) error {
	v := x.v
	if _, ok := v.d.connections[f.Connection]; !ok {
		return store.ErrNotFound
	}
	for conn, other := range v.d.flows {
		if conn == f.Connection {
			continue
		}
		if other.ID == f.ID {
			return fmt.Errorf("store: the flow id %s is taken", f.ID)
		}
		if len(f.StateHash) > 0 && bytes.Equal(other.StateHash, f.StateHash) {
			return errors.New("store: another flow holds the state hash")
		}
	}
	if err := checkJSON(f.Pending.Meta); err != nil {
		return err
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = v.now()
	}
	put(v, v.d.flows, f.Connection, cloneFlow(f))
	return nil
}

func (x viewFlows) Get(_ context.Context, connectionID string) (store.Flow, error) {
	f, ok := x.v.d.flows[connectionID]
	if !ok {
		return store.Flow{}, store.ErrNotFound
	}
	return cloneFlow(f), nil
}

func (x viewFlows) ByState(_ context.Context, h []byte) (store.Flow, error) {
	if len(h) == 0 {
		return store.Flow{}, store.ErrNotFound
	}
	for _, f := range x.v.d.flows {
		if bytes.Equal(f.StateHash, h) {
			return cloneFlow(f), nil
		}
	}
	return store.Flow{}, store.ErrNotFound
}

func (x viewFlows) Delete(_ context.Context, connectionID string) error {
	del(x.v, x.v.d.flows, connectionID)
	return nil
}

func (x viewFlows) TakeExpired(_ context.Context, now time.Time, limit int) ([]store.Flow, error) {
	v := x.v
	var expired []store.Flow
	for _, f := range v.d.flows {
		if f.ExpiresAt.Before(now) {
			expired = append(expired, f)
		}
	}
	slices.SortFunc(expired, func(a, b store.Flow) int {
		return cmp.Or(a.ExpiresAt.Compare(b.ExpiresAt), cmp.Compare(a.ID, b.ID))
	})
	if limit <= 0 {
		limit = store.SweepBatch
	}
	if len(expired) > limit {
		expired = expired[:limit]
	}
	out := make([]store.Flow, 0, len(expired))
	for _, f := range expired {
		del(v, v.d.flows, f.Connection)
		out = append(out, cloneFlow(f))
	}
	return out, nil
}

// --- registrations --------------------------------------------------------

type viewRegistrations struct{ v *view }

func cloneRegistration(r store.Registration) store.Registration {
	r.Secret = cloneSealed(r.Secret)
	return r
}

func (x viewRegistrations) Put(_ context.Context, r store.Registration) (store.Registration, error) {
	v := x.v
	k := [2]string{r.Issuer, r.RedirectURI}
	if kept, ok := v.d.registrations[k]; ok {
		return cloneRegistration(kept), nil
	}
	if r.RegisteredAt.IsZero() {
		r.RegisteredAt = v.now()
	}
	put(v, v.d.registrations, k, cloneRegistration(r))
	return cloneRegistration(r), nil
}

func (x viewRegistrations) Get(_ context.Context, issuer, redirectURI string) (store.Registration, error) {
	r, ok := x.v.d.registrations[[2]string{issuer, redirectURI}]
	if !ok {
		return store.Registration{}, store.ErrNotFound
	}
	return cloneRegistration(r), nil
}

func (x viewRegistrations) Delete(_ context.Context, issuer, redirectURI string) error {
	del(x.v, x.v.d.registrations, [2]string{issuer, redirectURI})
	return nil
}

// --- calls ----------------------------------------------------------------

type viewCalls struct{ v *view }

func (x viewCalls) Insert(_ context.Context, c store.Call) error {
	v := x.v
	if _, ok := v.d.calls[c.ID]; ok {
		return fmt.Errorf("store: the call id %s is taken", c.ID)
	}
	put(v, v.d.calls, c.ID, c)
	return nil
}

func (x viewCalls) List(_ context.Context, connectionID string, p store.Page) ([]store.Call, string, error) {
	var rows []store.Call
	for _, c := range x.v.d.calls {
		if c.Connection == connectionID {
			rows = append(rows, c)
		}
	}
	out, next := page(rows, func(c store.Call) string { return c.ID }, p)
	return out, next, nil
}

func (x viewCalls) Prune(_ context.Context, before time.Time, limit int) (int, error) {
	return prune(x.v, x.v.d.calls, func(c store.Call) time.Time { return c.At }, before, limit), nil
}

// prune removes up to limit rows older than before, oldest first.
func prune[K comparable, V any](v *view, m map[K]V, at func(V) time.Time, before time.Time, limit int) int {
	type row struct {
		k  K
		at time.Time
	}
	var old []row
	for k, val := range m {
		if t := at(val); t.Before(before) {
			old = append(old, row{k, t})
		}
	}
	slices.SortFunc(old, func(a, b row) int { return a.at.Compare(b.at) })
	if limit <= 0 {
		limit = store.SweepBatch
	}
	if len(old) > limit {
		old = old[:limit]
	}
	for _, r := range old {
		del(v, m, r.k)
	}
	return len(old)
}

// --- idempotency ----------------------------------------------------------

type viewIdempotency struct{ v *view }

func (x viewIdempotency) Put(_ context.Context, k store.IdempotencyKey) error {
	v := x.v
	key := [2]string{k.Subject, k.Key}
	if _, ok := v.d.idempotency[key]; ok {
		return store.ErrKeyTaken
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = v.now()
	}
	put(v, v.d.idempotency, key, k)
	return nil
}

func (x viewIdempotency) Get(_ context.Context, subject, key string) (store.IdempotencyKey, error) {
	k, ok := x.v.d.idempotency[[2]string{subject, key}]
	if !ok {
		return store.IdempotencyKey{}, store.ErrNotFound
	}
	return k, nil
}

func (x viewIdempotency) Prune(_ context.Context, before time.Time, limit int) (int, error) {
	return prune(x.v, x.v.d.idempotency, func(k store.IdempotencyKey) time.Time { return k.CreatedAt }, before, limit), nil
}

// --- rotation -------------------------------------------------------------

type viewRotation struct{ v *view }

// rewrapOne rewraps one value when a listed key other than the first holds
// it, and reports whether it did.
func rewrapOne(s *store.Sealed, keys store.KeyIDs, rewrap func(store.Sealed) (store.Sealed, error)) (bool, error) {
	if s.Zero() {
		return false, nil
	}
	if first, listed := keys.Under(s.KeyID); first || !listed {
		return false, nil
	}
	next, err := rewrap(*s)
	if err != nil {
		return false, err
	}
	*s = next
	return true, nil
}

func (x viewRotation) RewrapBatch(_ context.Context, table string, keys store.KeyIDs, limit int, rewrap func(store.Sealed) (store.Sealed, error)) (int, error) {
	v := x.v
	if limit <= 0 {
		limit = store.RewrapBatchSize
	}
	n := 0
	switch table {
	case store.TableCredentials:
		for _, id := range sortedKeys(v.d.credentials) {
			if n == limit {
				break
			}
			row := v.d.credentials[id]
			row.sealed = cloneCredential(row.sealed)
			did, err := rewrapOne(&row.sealed.Sealed, keys, rewrap)
			if err != nil {
				return n, err
			}
			if did {
				put(v, v.d.credentials, id, row)
				n++
			}
		}
	case store.TableFlows:
		for _, id := range sortedKeys(v.d.flows) {
			if n == limit {
				break
			}
			f := cloneFlow(v.d.flows[id])
			a, err := rewrapOne(&f.Verifier, keys, rewrap)
			if err != nil {
				return n, err
			}
			b, err := rewrapOne(&f.Pending.Sealed, keys, rewrap)
			if err != nil {
				return n, err
			}
			if a || b {
				put(v, v.d.flows, id, f)
				n++
			}
		}
	case store.TableRegistrations:
		ks := make([][2]string, 0, len(v.d.registrations))
		for k := range v.d.registrations {
			ks = append(ks, k)
		}
		slices.SortFunc(ks, func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) })
		for _, k := range ks {
			if n == limit {
				break
			}
			r := cloneRegistration(v.d.registrations[k])
			did, err := rewrapOne(&r.Secret, keys, rewrap)
			if err != nil {
				return n, err
			}
			if did {
				put(v, v.d.registrations, k, r)
				n++
			}
		}
	case store.TableConnectors:
		for _, id := range sortedKeys(v.d.connectors) {
			if n == limit {
				break
			}
			c := cloneConnector(v.d.connectors[id])
			did, err := rewrapOne(&c.ClientSecret, keys, rewrap)
			if err != nil {
				return n, err
			}
			if did {
				put(v, v.d.connectors, id, c)
				n++
			}
		}
	default:
		return 0, fmt.Errorf("store: %q is not a table with sealed values", table)
	}
	return n, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (x viewRotation) CountNotFirst(_ context.Context, keys store.KeyIDs) (map[string]store.KeyCount, error) {
	v := x.v
	out := map[string]store.KeyCount{}
	count := func(table string, s store.Sealed) {
		if s.Zero() {
			return
		}
		c := out[table]
		switch first, listed := keys.Under(s.KeyID); {
		case !listed:
			c.NoKey++
		case !first:
			c.NotFirst++
		}
		out[table] = c
	}
	for _, t := range store.SealedTables {
		out[t] = store.KeyCount{}
	}
	for _, row := range v.d.credentials {
		count(store.TableCredentials, row.sealed.Sealed)
	}
	for _, f := range v.d.flows {
		count(store.TableFlows, f.Verifier)
		count(store.TableFlows, f.Pending.Sealed)
	}
	for _, r := range v.d.registrations {
		count(store.TableRegistrations, r.Secret)
	}
	for _, c := range v.d.connectors {
		count(store.TableConnectors, c.ClientSecret)
	}
	return out, nil
}
