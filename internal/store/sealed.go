// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import "errors"

// The errors of sealing. Neither names a value or a key.
var (
	// ErrNoSealingKey is a seal asked of a server with no sealing key.
	ErrNoSealingKey = errors.New("store: no sealing key is configured")
	// ErrNotOpened is a sealed value no listed key opens, or whose binding
	// does not match.
	ErrNotOpened = errors.New("store: the sealed value does not open")
)

// Sealed is one sealed value, as its five columns.
type Sealed struct {
	KeyID      []byte // 8 bytes: the sealing key that wrapped the data key
	WrappedKey []byte // the data key, sealed under that key
	KeyNonce   []byte // 12 bytes
	Ciphertext []byte // the value, sealed under the data key
	Nonce      []byte // 12 bytes
}

// Zero reports whether nothing is sealed.
func (s Sealed) Zero() bool { return len(s.Ciphertext) == 0 }

// Binding is what a sealed value is tied to: its additional data.
type Binding []string

// Sealer seals and opens values under the sealing keys.
type Sealer interface {
	// Seal seals plaintext under a fresh data key, bound to b:
	// ErrNoSealingKey.
	Seal(plaintext []byte, b Binding) (Sealed, error)
	// Open opens a value under its binding: ErrNotOpened.
	Open(s Sealed, b Binding) ([]byte, error)
	// Rewrap wraps the data key under the first key, reading no
	// ciphertext.
	Rewrap(s Sealed) (Sealed, error)
	// Keys names the keys, for a rotation.
	Keys() KeyIDs
}
