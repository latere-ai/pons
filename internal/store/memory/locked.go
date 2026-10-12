// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"time"

	"latere.ai/x/pons/internal/store"
)

// The tables outside a transaction: each call is a transaction of its own.

type connectors struct{ s *Store }

func (x connectors) Create(ctx context.Context, c store.Connector) error {
	return x.s.one(ctx, func(v *view) error { return v.Connectors().Create(ctx, c) })
}

func (x connectors) Get(ctx context.Context, id string) (out store.Connector, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Connectors().Get(ctx, id); return err })
	return out, err
}

func (x connectors) List(ctx context.Context, owners []string, p store.Page) (out []store.Connector, next string, err error) {
	err = x.s.one(ctx, func(v *view) error { out, next, err = v.Connectors().List(ctx, owners, p); return err })
	return out, next, err
}

func (x connectors) Delete(ctx context.Context, id string) error {
	return x.s.one(ctx, func(v *view) error { return v.Connectors().Delete(ctx, id) })
}

type connections struct{ s *Store }

func (x connections) Create(ctx context.Context, c store.Connection, max int) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Create(ctx, c, max) })
}

func (x connections) Get(ctx context.Context, id string) (out store.Connection, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Connections().Get(ctx, id); return err })
	return out, err
}

func (x connections) List(ctx context.Context, f store.Filter, p store.Page) (out []store.Connection, next string, err error) {
	err = x.s.one(ctx, func(v *view) error { out, next, err = v.Connections().List(ctx, f, p); return err })
	return out, next, err
}

func (x connections) Rename(ctx context.Context, id, name string) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Rename(ctx, id, name) })
}

func (x connections) Move(ctx context.Context, id string, from, to store.State, reason string) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Move(ctx, id, from, to, reason) })
}

func (x connections) Describe(ctx context.Context, id string, a store.Account) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Describe(ctx, id, a) })
}

func (x connections) Touch(ctx context.Context, id string, at time.Time) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Touch(ctx, id, at) })
}

func (x connections) Delete(ctx context.Context, id string) error {
	return x.s.one(ctx, func(v *view) error { return v.Connections().Delete(ctx, id) })
}

func (x connections) CountByState(ctx context.Context) (out map[store.State]int64, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Connections().CountByState(ctx); return err })
	return out, err
}

func (x connections) InUse(ctx context.Context, connector string) (used bool, err error) {
	err = x.s.one(ctx, func(v *view) error { used, err = v.Connections().InUse(ctx, connector); return err })
	return used, err
}

type credentials struct{ s *Store }

func (x credentials) Put(ctx context.Context, connectionID string, c store.SealedCredential) (version int64, err error) {
	err = x.s.one(ctx, func(v *view) error { version, err = v.Credentials().Put(ctx, connectionID, c); return err })
	return version, err
}

func (x credentials) Get(ctx context.Context, connectionID string) (c store.SealedCredential, version int64, err error) {
	err = x.s.one(ctx, func(v *view) error { c, version, err = v.Credentials().Get(ctx, connectionID); return err })
	return c, version, err
}

func (x credentials) ClaimRefresh(ctx context.Context, connectionID string, lease time.Duration) (claimed bool, version int64, err error) {
	err = x.s.one(ctx, func(v *view) error {
		claimed, version, err = v.Credentials().ClaimRefresh(ctx, connectionID, lease)
		return err
	})
	return claimed, version, err
}

func (x credentials) CompleteRefresh(ctx context.Context, connectionID string, fromVersion int64, sealed store.SealedCredential) error {
	return x.s.one(ctx, func(v *view) error {
		return v.Credentials().CompleteRefresh(ctx, connectionID, fromVersion, sealed)
	})
}

func (x credentials) ReleaseRefresh(ctx context.Context, connectionID string) error {
	return x.s.one(ctx, func(v *view) error { return v.Credentials().ReleaseRefresh(ctx, connectionID) })
}

type flows struct{ s *Store }

func (x flows) Put(ctx context.Context, f store.Flow) error {
	return x.s.one(ctx, func(v *view) error { return v.Flows().Put(ctx, f) })
}

func (x flows) Get(ctx context.Context, connectionID string) (out store.Flow, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Flows().Get(ctx, connectionID); return err })
	return out, err
}

func (x flows) ByState(ctx context.Context, h []byte) (out store.Flow, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Flows().ByState(ctx, h); return err })
	return out, err
}

func (x flows) Delete(ctx context.Context, connectionID string) error {
	return x.s.one(ctx, func(v *view) error { return v.Flows().Delete(ctx, connectionID) })
}

func (x flows) TakeExpired(ctx context.Context, now time.Time, limit int) (out []store.Flow, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Flows().TakeExpired(ctx, now, limit); return err })
	return out, err
}

type registrations struct{ s *Store }

func (x registrations) Put(ctx context.Context, r store.Registration) (out store.Registration, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Registrations().Put(ctx, r); return err })
	return out, err
}

func (x registrations) Get(ctx context.Context, issuer, redirectURI string) (out store.Registration, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Registrations().Get(ctx, issuer, redirectURI); return err })
	return out, err
}

func (x registrations) Delete(ctx context.Context, issuer, redirectURI string) error {
	return x.s.one(ctx, func(v *view) error { return v.Registrations().Delete(ctx, issuer, redirectURI) })
}

type calls struct{ s *Store }

func (x calls) Insert(ctx context.Context, c store.Call) error {
	return x.s.one(ctx, func(v *view) error { return v.Calls().Insert(ctx, c) })
}

func (x calls) List(ctx context.Context, connectionID string, p store.Page) (out []store.Call, next string, err error) {
	err = x.s.one(ctx, func(v *view) error { out, next, err = v.Calls().List(ctx, connectionID, p); return err })
	return out, next, err
}

func (x calls) Prune(ctx context.Context, before time.Time, limit int) (n int, err error) {
	err = x.s.one(ctx, func(v *view) error { n, err = v.Calls().Prune(ctx, before, limit); return err })
	return n, err
}

type idempotency struct{ s *Store }

func (x idempotency) Put(ctx context.Context, k store.IdempotencyKey) error {
	return x.s.one(ctx, func(v *view) error { return v.Idempotency().Put(ctx, k) })
}

func (x idempotency) Get(ctx context.Context, subject, key string) (out store.IdempotencyKey, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Idempotency().Get(ctx, subject, key); return err })
	return out, err
}

func (x idempotency) Prune(ctx context.Context, before time.Time, limit int) (n int, err error) {
	err = x.s.one(ctx, func(v *view) error { n, err = v.Idempotency().Prune(ctx, before, limit); return err })
	return n, err
}

type rotation struct{ s *Store }

func (x rotation) RewrapBatch(ctx context.Context, table string, keys store.KeyIDs, limit int, rewrap func(store.Sealed) (store.Sealed, error)) (n int, err error) {
	err = x.s.one(ctx, func(v *view) error { n, err = v.Rotation().RewrapBatch(ctx, table, keys, limit, rewrap); return err })
	return n, err
}

func (x rotation) CountNotFirst(ctx context.Context, keys store.KeyIDs) (out map[string]store.KeyCount, err error) {
	err = x.s.one(ctx, func(v *view) error { out, err = v.Rotation().CountNotFirst(ctx, keys); return err })
	return out, err
}
