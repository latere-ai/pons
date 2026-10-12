// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/storetest"
)

// meta is what a credential of the tests keeps in the clear.
var meta = store.Meta{
	Issuer: "https://auth.example.com", TokenEndpoint: "https://auth.example.com/token",
	RevocationEndpoint: "https://auth.example.com/revoke",
}

func credentialBinding() store.Binding {
	return store.CredentialBinding("con_a", "alice", store.KindOAuth, meta, "")
}

// A sealed value opens under its binding alone: copied to another
// connection, owner or kind, or from a verifier into a credential, it does
// not open.
func TestACopiedCiphertextDoesNotOpen(t *testing.T) {
	s := storetest.Sealer(t, 1)
	sealed, err := s.Seal([]byte("access-token-canary"), credentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := s.Open(sealed, credentialBinding()); err != nil || string(plain) != "access-token-canary" {
		t.Fatalf("the value does not open under its own binding: %v", err)
	}
	for name, b := range map[string]store.Binding{
		"another connection": store.CredentialBinding("con_b", "alice", store.KindOAuth, meta, ""),
		"another owner":      store.CredentialBinding("con_a", "bob", store.KindOAuth, meta, ""),
		"another kind":       store.CredentialBinding("con_a", "alice", store.KindToken, meta, ""),
		"a verifier":         store.VerifierBinding("con_a", "alice"),
		"a registration":     store.RegistrationBinding("con_a", "alice"),
		"members shifted":    {"credential", "con_aalice", "", store.KindOAuth, meta.Issuer, meta.TokenEndpoint, meta.RevocationEndpoint, ""},
	} {
		if _, err := s.Open(sealed, b); !errors.Is(err, store.ErrNotOpened) {
			t.Errorf("copied to %s: %v", name, err)
		}
	}
	verifier, err := s.Seal([]byte("verifier-canary"), store.VerifierBinding("flw_1", "con_a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(verifier, credentialBinding()); !errors.Is(err, store.ErrNotOpened) {
		t.Errorf("a verifier opened as a credential: %v", err)
	}
}

// A credential whose issuer, token endpoint or revocation endpoint was
// rewritten in the clear, or whose added connector's url was, does not
// open, so nothing is sent to the new address.
func TestRewrittenEndpointDoesNotOpen(t *testing.T) {
	s := storetest.Sealer(t, 1)
	added := "https://wiki.example.com/mcp"
	sealed, err := s.Seal([]byte("access-token-canary"), store.CredentialBinding("con_a", "alice", store.KindOAuth, meta, added))
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(f func(*store.Meta)) store.Meta { m := meta; f(&m); return m }
	for name, b := range map[string]store.Binding{
		"issuer":              store.CredentialBinding("con_a", "alice", store.KindOAuth, rewrite(func(m *store.Meta) { m.Issuer = "https://evil.example.net" }), added),
		"token endpoint":      store.CredentialBinding("con_a", "alice", store.KindOAuth, rewrite(func(m *store.Meta) { m.TokenEndpoint = "https://evil.example.net/token" }), added),
		"revocation endpoint": store.CredentialBinding("con_a", "alice", store.KindOAuth, rewrite(func(m *store.Meta) { m.RevocationEndpoint = "" }), added),
		"connector url":       store.CredentialBinding("con_a", "alice", store.KindOAuth, meta, "https://evil.example.net/mcp"),
	} {
		if _, err := s.Open(sealed, b); !errors.Is(err, store.ErrNotOpened) {
			t.Errorf("a rewritten %s opened: %v", name, err)
		}
	}
}

// Two seals of one value share no column but key_id.
func TestEverySealIsFresh(t *testing.T) {
	s := storetest.Sealer(t, 1)
	a, err := s.Seal([]byte("access-token-canary"), credentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Seal([]byte("access-token-canary"), credentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.KeyID, b.KeyID) {
		t.Fatal("two seals under one key name two keys")
	}
	for name, pair := range map[string][2][]byte{
		"wrapped key": {a.WrappedKey, b.WrappedKey}, "key nonce": {a.KeyNonce, b.KeyNonce},
		"ciphertext": {a.Ciphertext, b.Ciphertext}, "nonce": {a.Nonce, b.Nonce},
	} {
		if bytes.Equal(pair[0], pair[1]) {
			t.Errorf("two seals share the %s", name)
		}
	}
	if len(a.KeyID) != store.KeyIDSize || len(a.KeyNonce) != store.NonceSize || len(a.Nonce) != store.NonceSize {
		t.Fatalf("the columns are %d, %d and %d bytes", len(a.KeyID), len(a.KeyNonce), len(a.Nonce))
	}
}

// The first key wraps, every listed key opens, a key's id is the first 8
// bytes of its SHA-256, and a repeated key is refused naming positions and
// no key.
func TestTheKeyList(t *testing.T) {
	var k1, k2 [store.KeySize]byte
	for i := range k1 {
		k1[i], k2[i] = 1, 2
	}
	old, err := store.NewSealer(k1)
	if err != nil {
		t.Fatal(err)
	}
	both, err := store.NewSealer(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	sum1, sum2 := sha256.Sum256(k1[:]), sha256.Sum256(k2[:])
	keys := both.Keys()
	if !bytes.Equal(keys.First, sum2[:8]) || len(keys.Listed) != 2 || !bytes.Equal(keys.Listed[1], sum1[:8]) {
		t.Fatalf("the key ids %x", keys)
	}
	sealed, err := old.Seal([]byte("value-canary"), credentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed.KeyID, sum1[:8]) {
		t.Fatal("the key id is not the first 8 bytes of the key's SHA-256")
	}
	// Every listed key opens, the first or not, and whatever the row's key
	// id says.
	if _, err := both.Open(sealed, credentialBinding()); err != nil {
		t.Fatalf("a listed key does not open: %v", err)
	}
	misnamed := sealed
	misnamed.KeyID = sum2[:8]
	if _, err := both.Open(misnamed, credentialBinding()); err != nil {
		t.Fatalf("a value whose key id is wrong does not open under the other key: %v", err)
	}
	fresh, err := both.Seal([]byte("value-canary"), credentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh.KeyID, sum2[:8]) {
		t.Fatal("the first key does not wrap")
	}
	if _, err := old.Open(fresh, credentialBinding()); !errors.Is(err, store.ErrNotOpened) {
		t.Fatalf("a key that is not listed opened: %v", err)
	}

	// A rewrap moves the data key under the first key and keeps the rest.
	rewrapped, err := both.Rewrap(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewrapped.KeyID, sum2[:8]) || !bytes.Equal(rewrapped.Ciphertext, sealed.Ciphertext) || !bytes.Equal(rewrapped.Nonce, sealed.Nonce) {
		t.Fatal("the rewrap changed more than the wrap")
	}
	newOnly, err := store.NewSealer(k2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOnly.Open(rewrapped, credentialBinding()); err != nil {
		t.Fatalf("the rewrapped value does not open under the new key alone: %v", err)
	}
	if _, err := newOnly.Rewrap(sealed); !errors.Is(err, store.ErrNotOpened) {
		t.Fatalf("a value under no listed key was rewrapped: %v", err)
	}

	// A key listed twice.
	_, err = store.NewSealer(k1, k2, k1)
	if err == nil || !strings.Contains(err.Error(), "position 1") || !strings.Contains(err.Error(), "position 3") {
		t.Fatalf("a repeated key: %v", err)
	}
	if strings.Contains(err.Error(), string(k1[:])) || strings.Contains(err.Error(), "0101") {
		t.Fatal("the error prints the key")
	}

	// No key at all seals nothing and opens nothing.
	none, err := store.NewSealer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := none.Seal([]byte("x"), nil); !errors.Is(err, store.ErrNoSealingKey) {
		t.Fatalf("a seal with no key: %v", err)
	}
	if _, err := none.Open(sealed, credentialBinding()); !errors.Is(err, store.ErrNotOpened) {
		t.Fatalf("an open with no key: %v", err)
	}
	if _, err := none.Rewrap(sealed); !errors.Is(err, store.ErrNoSealingKey) {
		t.Fatalf("a rewrap with no key: %v", err)
	}
	if k := none.Keys(); len(k.First) != 0 || len(k.Listed) != 0 {
		t.Fatalf("no key names %x", k)
	}

	// A value whose columns were cut short does not open.
	for name, broken := range map[string]store.Sealed{
		"key nonce":  {KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, KeyNonce: sealed.KeyNonce[:4], Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce},
		"nonce":      {KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, KeyNonce: sealed.KeyNonce, Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce[:4]},
		"ciphertext": {KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, KeyNonce: sealed.KeyNonce, Ciphertext: sealed.Ciphertext[:4], Nonce: sealed.Nonce},
		"wrap":       {KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey[:4], KeyNonce: sealed.KeyNonce, Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce},
	} {
		if _, err := both.Open(broken, credentialBinding()); !errors.Is(err, store.ErrNotOpened) {
			t.Errorf("a value with a cut %s: %v", name, err)
		}
	}
	if !(store.Sealed{}).Zero() || sealed.Zero() {
		t.Fatal("Zero")
	}
}

// The plaintext and the meta round trip, and an empty meta reads as none.
func TestCredentialDocuments(t *testing.T) {
	plain, err := store.Secrets{AccessToken: "a-token", RefreshToken: "r-token"}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.DecodeSecrets(plain)
	if err != nil || got.AccessToken != "a-token" || got.RefreshToken != "r-token" || got.Value != "" {
		t.Fatalf("secrets %+v, %v", got, err)
	}
	if strings.Contains(string(plain), "value") || strings.Contains(string(plain), "client_secret") {
		t.Fatalf("an oauth plaintext carries the members of other kinds: %s", plain)
	}
	m, err := store.EncodeMeta(store.Meta{Header: "X-Api-Key", Format: "{value}"})
	if err != nil {
		t.Fatal(err)
	}
	back, err := store.DecodeMeta(m)
	if err != nil || back.Header != "X-Api-Key" || back.Format != "{value}" || back.Issuer != "" {
		t.Fatalf("meta %+v, %v", back, err)
	}
	if string(m) != `{"header":"X-Api-Key","format":"{value}"}` {
		t.Fatalf("a token's meta carries more than its members: %s", m)
	}
	if none, err := store.DecodeMeta(nil); err != nil || none.Issuer != "" {
		t.Fatalf("an empty meta: %+v, %v", none, err)
	}
	if _, err := store.DecodeMeta([]byte("{")); err == nil {
		t.Fatal("a meta that is not JSON was read")
	}
	if _, err := store.DecodeSecrets([]byte("{")); err == nil {
		t.Fatal("a plaintext that is not JSON was read")
	}
}

// The reason after a move follows the rule both adapters apply.
func TestNextReason(t *testing.T) {
	cases := []struct {
		from, to       store.State
		current, given string
		want           string
	}{
		{store.StatePending, store.StateConnected, "revoked", "x", ""},
		{store.StateConnected, store.StateNeedsReconnect, "", "revoked", "revoked"},
		{store.StateConnected, store.StateNeedsReconnect, "old", "", "old"},
		{store.StatePending, store.StatePending, "old", "refresh_refused", "refresh_refused"},
		{store.StatePending, store.StatePending, "old", "", "old"},
		{store.StateNeedsReconnect, store.StatePending, "revoked", "x", "revoked"},
		{store.StateConnected, store.StatePending, "", "x", ""},
	}
	for _, c := range cases {
		if got := store.NextReason(c.from, c.to, c.current, c.given); got != c.want {
			t.Errorf("%s to %s from %q given %q: %q, want %q", c.from, c.to, c.current, c.given, got, c.want)
		}
	}
	if (store.Page{}).Size() != store.DefaultLimit || (store.Page{Limit: 1000}).Size() != store.MaxLimit || (store.Page{Limit: 7}).Size() != 7 {
		t.Fatal("a page's size")
	}
}
