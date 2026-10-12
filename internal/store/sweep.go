// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"
)

// The bounds of the sweeps the store owns.
const (
	// SweepBatch is how many rows one Prune removes at most.
	SweepBatch = 1000
	// IdempotencyTTL is how long an idempotency key is kept.
	IdempotencyTTL = 24 * time.Hour
	// RewrapBatchSize is how many rows one rewrap batch takes.
	RewrapBatchSize = 100
)

// The bounds of a page.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Size is the number of rows a page holds: Limit, 50 when it is zero or
// below, and 200 at most.
func (p Page) Size() int {
	switch {
	case p.Limit <= 0:
		return DefaultLimit
	case p.Limit > MaxLimit:
		return MaxLimit
	}
	return p.Limit
}

// Sweep removes the call records older than the retention, in batches of
// SweepBatch until a batch removes fewer, and then the idempotency keys
// older than IdempotencyTTL the same way (specs/010-records-and-observability.md).
// Two replicas sweeping at once remove each row once.
func Sweep(ctx context.Context, st Store, now time.Time, retention time.Duration) (calls, keys int, err error) {
	for {
		n, err := st.Calls().Prune(ctx, now.Add(-retention), SweepBatch)
		calls += n
		if err != nil {
			return calls, keys, fmt.Errorf("store: sweeping the call records: %w", err)
		}
		if n < SweepBatch {
			break
		}
	}
	for {
		n, err := st.Idempotency().Prune(ctx, now.Add(-IdempotencyTTL), SweepBatch)
		keys += n
		if err != nil {
			return calls, keys, fmt.Errorf("store: sweeping the idempotency keys: %w", err)
		}
		if n < SweepBatch {
			break
		}
	}
	return calls, keys, nil
}

// Rewrap moves every sealed value under a listed key other than the first
// under the first, table by table, batch by batch, until a batch rewraps
// none. It reads no ciphertext. A value under no listed key is in no batch.
// It answers how many rows it rewrote.
func Rewrap(ctx context.Context, st Store, s Sealer, batch int) (int, error) {
	keys := s.Keys()
	if len(keys.First) == 0 {
		return 0, nil
	}
	total := 0
	for _, table := range SealedTables {
		for {
			n, err := st.Rotation().RewrapBatch(ctx, table, keys, batch, s.Rewrap)
			total += n
			if err != nil {
				return total, fmt.Errorf("store: rewrapping %s: %w", table, err)
			}
			if n == 0 {
				break
			}
		}
	}
	return total, nil
}

// Remaining is what a rotation has left, per table: the sealed values under
// a listed key other than the first, and those under no listed key.
func Remaining(ctx context.Context, st Store, s Sealer) (map[string]KeyCount, error) {
	return st.Rotation().CountNotFirst(ctx, s.Keys())
}
