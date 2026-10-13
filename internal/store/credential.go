// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"errors"
	"time"
)

// MinSecretBytes is the shortest credential value accepted: a shorter one
// cannot be searched for safely by a canary test.
const MinSecretBytes = 8

// ErrShortSecret is a credential value shorter than MinSecretBytes.
var ErrShortSecret = errors.New("store: a credential value is shorter than 8 bytes")

// Meta is what specs/002-objects.md keeps in the clear beside a credential
// of each kind, as credentials.meta. A member a kind does not have is left
// out.
type Meta struct {
	// oauth
	TokenType          string    `json:"token_type,omitempty"`
	AccessExpiresAt    time.Time `json:"access_expires_at,omitzero"`
	RefreshExpiresAt   time.Time `json:"refresh_expires_at,omitzero"`
	Issuer             string    `json:"issuer,omitempty"`
	TokenEndpoint      string    `json:"token_endpoint,omitempty"`
	RevocationEndpoint string    `json:"revocation_endpoint,omitempty"`
	Resource           string    `json:"resource,omitempty"`
	// oauth and client_credentials
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	// client_credentials
	Audience string `json:"audience,omitempty"`
	// token: the header the key is placed in, and its format
	Header string `json:"header,omitempty"`
	Format string `json:"format,omitempty"`
	// Account is the account a sign-in read, kept beside a flow's pending
	// credential until the confirm writes it to the connection.
	Account string `json:"account,omitempty"`
}

// Secrets is a credential's plaintext: one JSON document of the members
// specs/002-objects.md lists as sealed for its kind. It exists between a
// request and a seal, and between an open and a forwarded call, and nowhere
// else.
type Secrets struct {
	AccessToken  string `json:"access_token,omitempty"`  // oauth
	RefreshToken string `json:"refresh_token,omitempty"` // oauth
	Value        string `json:"value,omitempty"`         // token
	ClientSecret string `json:"client_secret,omitempty"` // client_credentials
}

// Encode is the plaintext a seal takes.
func (s Secrets) Encode() ([]byte, error) { return json.Marshal(s) }

// DecodeSecrets reads an opened plaintext.
func DecodeSecrets(b []byte) (Secrets, error) {
	var s Secrets
	err := json.Unmarshal(b, &s)
	return s, err
}

// EncodeMeta is the meta column.
func EncodeMeta(m Meta) (json.RawMessage, error) { return json.Marshal(m) }

// DecodeMeta reads the meta column.
func DecodeMeta(b json.RawMessage) (Meta, error) {
	var m Meta
	if len(b) == 0 {
		return m, nil
	}
	err := json.Unmarshal(b, &m)
	return m, err
}

// CredentialBinding is what a connection's credential is bound to, and a
// flow's pending credential too: the connection, its owner, the kind, the
// issuer and the endpoints kept in meta, and the url of a connector a
// person added, empty for a catalog connector. A ciphertext copied to
// another connection, owner or kind, or one whose endpoints or connector url
// were rewritten in the clear, does not open.
func CredentialBinding(connectionID, owner, kind string, m Meta, addedURL string) Binding {
	return Binding{"credential", connectionID, owner, kind, m.Issuer, m.TokenEndpoint, m.RevocationEndpoint, addedURL}
}

// VerifierBinding is what a flow's proof-key verifier is bound to.
func VerifierBinding(flowID, connectionID string) Binding {
	return Binding{"verifier", flowID, connectionID}
}

// RegistrationBinding is what a registration's client secret is bound to.
func RegistrationBinding(issuer, redirectURI string) Binding {
	return Binding{"registration", issuer, redirectURI}
}
