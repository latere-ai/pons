// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// The sizes of the sealing of specs/005-store-and-sealing.md.
const (
	// KeySize is the length of a sealing key and of a data key.
	KeySize = 32
	// KeyIDSize is the length of a key's id: the first bytes of the
	// SHA-256 of the key.
	KeyIDSize = 8
	// NonceSize is the length of both nonces, 96 bits.
	NonceSize = 12
)

// KeySealer seals under the sealing keys of PONS_SEALING_KEYS. A fresh data
// key seals each value with AES-256-GCM, with the value's binding as the
// additional data; the data key is wrapped with AES-256-GCM, under a nonce
// of its own and with no additional data, by the first key. The wrap
// carrying no additional data is what lets a rotation rewrite the wrapped
// key and nothing else.
type KeySealer struct {
	keys []sealingKey // the first wraps
}

// sealingKey is one listed key, ready to wrap and unwrap.
type sealingKey struct {
	id   []byte
	aead cipher.AEAD
}

// NewSealer builds the sealer over the listed keys, the first wrapping. No
// key at all is a sealer that seals nothing and opens nothing, which is
// what a server on the memory store without a key runs. A key listed twice
// is refused, naming the positions and never the key.
func NewSealer(keys ...[KeySize]byte) (*KeySealer, error) {
	s := &KeySealer{}
	for i, k := range keys {
		id := keyID(k[:])
		for j, other := range s.keys {
			if bytes.Equal(other.id, id) {
				return nil, fmt.Errorf("store: the sealing key at position %d is listed again at position %d", j+1, i+1)
			}
		}
		aead, err := newAEAD(k[:])
		if err != nil {
			return nil, fmt.Errorf("store: the sealing key at position %d: %w", i+1, err)
		}
		s.keys = append(s.keys, sealingKey{id: id, aead: aead})
	}
	return s, nil
}

// keyID is the first 8 bytes of the SHA-256 of a key.
func keyID(k []byte) []byte {
	sum := sha256.Sum256(k)
	return bytes.Clone(sum[:KeyIDSize])
}

// newAEAD is AES-256-GCM over a 32-byte key.
func newAEAD(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Keys names the keys: the one that wraps and every listed one.
func (s *KeySealer) Keys() KeyIDs {
	var ids KeyIDs
	for i, k := range s.keys {
		if i == 0 {
			ids.First = bytes.Clone(k.id)
		}
		ids.Listed = append(ids.Listed, bytes.Clone(k.id))
	}
	return ids
}

// Seal seals plaintext under a fresh data key, bound to b.
func (s *KeySealer) Seal(plaintext []byte, b Binding) (Sealed, error) {
	if len(s.keys) == 0 {
		return Sealed{}, ErrNoSealingKey
	}
	dataKey := make([]byte, KeySize)
	defer clear(dataKey)
	nonce := make([]byte, NonceSize)
	keyNonce := make([]byte, NonceSize)
	// crypto/rand.Read does not fail: it aborts the process when the
	// system's source is unavailable.
	_, _ = rand.Read(dataKey)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(keyNonce)
	value, err := newAEAD(dataKey)
	if err != nil {
		return Sealed{}, err
	}
	first := s.keys[0]
	return Sealed{
		KeyID:      bytes.Clone(first.id),
		WrappedKey: first.aead.Seal(nil, keyNonce, dataKey, nil),
		KeyNonce:   keyNonce,
		Ciphertext: value.Seal(nil, nonce, plaintext, b.encode()),
		Nonce:      nonce,
	}, nil
}

// Open opens a value under its binding. A value no listed key unwraps, or
// whose binding does not match, is ErrNotOpened.
func (s *KeySealer) Open(sealed Sealed, b Binding) ([]byte, error) {
	dataKey, err := s.unwrap(sealed)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	if len(sealed.Nonce) != NonceSize {
		return nil, ErrNotOpened
	}
	value, err := newAEAD(dataKey)
	if err != nil {
		return nil, ErrNotOpened
	}
	plaintext, err := value.Open(nil, sealed.Nonce, sealed.Ciphertext, b.encode())
	if err != nil {
		return nil, ErrNotOpened
	}
	return plaintext, nil
}

// Rewrap wraps a value's data key under the first key, under a fresh nonce.
// It reads no ciphertext: the value and its nonce are kept as they are.
func (s *KeySealer) Rewrap(sealed Sealed) (Sealed, error) {
	if len(s.keys) == 0 {
		return Sealed{}, ErrNoSealingKey
	}
	dataKey, err := s.unwrap(sealed)
	if err != nil {
		return Sealed{}, err
	}
	defer clear(dataKey)
	keyNonce := make([]byte, NonceSize)
	_, _ = rand.Read(keyNonce)
	first := s.keys[0]
	return Sealed{
		KeyID:      bytes.Clone(first.id),
		WrappedKey: first.aead.Seal(nil, keyNonce, dataKey, nil),
		KeyNonce:   keyNonce,
		Ciphertext: bytes.Clone(sealed.Ciphertext),
		Nonce:      bytes.Clone(sealed.Nonce),
	}, nil
}

// unwrap opens a value's data key: under the key whose id the value names
// first, then under every other listed key.
func (s *KeySealer) unwrap(sealed Sealed) ([]byte, error) {
	if len(sealed.KeyNonce) != NonceSize {
		return nil, ErrNotOpened
	}
	order := make([]sealingKey, 0, len(s.keys))
	for _, k := range s.keys {
		if bytes.Equal(k.id, sealed.KeyID) {
			order = append([]sealingKey{k}, order...)
		} else {
			order = append(order, k)
		}
	}
	for _, k := range order {
		dataKey, err := k.aead.Open(nil, sealed.KeyNonce, sealed.WrappedKey, nil)
		if err == nil && len(dataKey) == KeySize {
			return dataKey, nil
		}
	}
	return nil, ErrNotOpened
}

// encode writes each member as its length in 4 bytes and its bytes, so no
// two bindings share an encoding.
func (b Binding) encode() []byte {
	var out []byte
	for _, m := range b {
		out = binary.BigEndian.AppendUint32(out, uint32(len(m)))
		out = append(out, m...)
	}
	return out
}

// Under reports where a sealed value stands against the keys: under the
// first key, under another listed key, or under none.
func (k KeyIDs) Under(id []byte) (first, listed bool) {
	for _, l := range k.Listed {
		if bytes.Equal(l, id) {
			return bytes.Equal(k.First, id), true
		}
	}
	return false, false
}
