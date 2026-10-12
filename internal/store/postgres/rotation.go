// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"latere.ai/x/pons/internal/store"
)

type rotation struct{ v *view }

// sealedSet is the prefix of one sealed value's five columns in a table.
type sealedSet struct {
	prefix string
}

// cols are the five columns of the set.
func (s sealedSet) cols() string {
	p := s.prefix
	return p + "key_id, " + p + "wrapped_key, " + p + "key_nonce, " + p + "ciphertext, " + p + "nonce"
}

// sealedTables are the tables that hold sealed values: the columns that
// name a row, and each set of sealed columns.
var sealedTables = map[string]struct {
	key  string
	sets []sealedSet
}{
	store.TableCredentials:   {key: "connection", sets: []sealedSet{{""}}},
	store.TableFlows:         {key: "id", sets: []sealedSet{{"verifier_"}, {"pending_"}}},
	store.TableRegistrations: {key: "issuer || chr(31) || redirect_uri", sets: []sealedSet{{"secret_"}}},
}

// others are the listed keys other than the first.
func others(keys store.KeyIDs) [][]byte {
	var out [][]byte
	for _, k := range keys.Listed {
		if !bytes.Equal(k, keys.First) {
			out = append(out, k)
		}
	}
	return out
}

func (x rotation) RewrapBatch(ctx context.Context, table string, keys store.KeyIDs, limit int, rewrap func(store.Sealed) (store.Sealed, error)) (int, error) {
	t, ok := sealedTables[table]
	if !ok {
		return 0, fmt.Errorf("store: %q is not a table with sealed values", table)
	}
	stale := others(keys)
	if len(keys.First) == 0 || len(stale) == 0 {
		return 0, nil
	}
	if limit <= 0 {
		limit = store.RewrapBatchSize
	}
	conds := make([]string, 0, len(t.sets))
	cols := []string{t.key}
	for _, s := range t.sets {
		conds = append(conds, s.prefix+"key_id = ANY($1)")
		cols = append(cols, s.cols())
	}
	selected, where := strings.Join(cols, ", "), strings.Join(conds, " OR ")
	n := 0
	// One short transaction that locks its rows and skips rows another
	// replica holds, so replicas share the work and a refresh waits one
	// batch at most. Only the key columns are written: the ciphertext a
	// refresh writes after this batch is its own.
	err := x.v.atomic(ctx, func(q querier) error {
		rows, err := q.Query(ctx, `SELECT `+selected+` FROM `+table+` WHERE `+where+
			` ORDER BY 1 LIMIT $2 FOR UPDATE SKIP LOCKED`, stale, limit)
		if err != nil {
			return err
		}
		type row struct {
			key    string
			sealed []store.Sealed
		}
		var batch []row
		for rows.Next() {
			r := row{sealed: make([]store.Sealed, len(t.sets))}
			dest := []any{&r.key}
			for i := range t.sets {
				s := &r.sealed[i]
				dest = append(dest, &s.KeyID, &s.WrappedKey, &s.KeyNonce, &s.Ciphertext, &s.Nonce)
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range batch {
			for i, set := range t.sets {
				s := r.sealed[i]
				if s.Zero() {
					continue
				}
				if first, listed := keys.Under(s.KeyID); first || !listed {
					continue
				}
				next, err := rewrap(s)
				if err != nil {
					return err
				}
				p := set.prefix
				if _, err := q.Exec(ctx, `UPDATE `+table+` SET `+p+`key_id = $2, `+p+`wrapped_key = $3, `+p+`key_nonce = $4
WHERE `+t.key+` = $1 AND `+p+`key_id = $5`, r.key, next.KeyID, next.WrappedKey, next.KeyNonce, s.KeyID); err != nil {
					return err
				}
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (x rotation) CountNotFirst(ctx context.Context, keys store.KeyIDs) (map[string]store.KeyCount, error) {
	out := map[string]store.KeyCount{}
	listed := keys.Listed
	if listed == nil {
		listed = [][]byte{}
	}
	for _, table := range store.SealedTables {
		t := sealedTables[table]
		var c store.KeyCount
		for _, s := range t.sets {
			col := s.prefix + "key_id"
			var notFirst, noKey int64
			err := x.v.q.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE `+col+` = ANY($1) AND `+col+` IS DISTINCT FROM $2),
       count(*) FILTER (WHERE NOT (`+col+` = ANY($1)))
  FROM `+table+` WHERE `+col+` IS NOT NULL`, listed, nullable(keys.First)).Scan(&notFirst, &noKey)
			if err != nil {
				return nil, err
			}
			c.NotFirst += notFirst
			c.NoKey += noKey
		}
		out[table] = c
	}
	return out, nil
}
