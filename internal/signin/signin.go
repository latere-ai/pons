// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package signin is Pons as an OAuth client toward the other service
// (specs/007-sign-in.md): discovery, how Pons identifies itself, the
// authorization request and its flow, the callback, the confirm, the token
// endpoint and its habits, refresh by one writer, a token minted at use,
// revocation, and the sweep of flows that ran out. Every request goes
// through the outside client of internal/dial, and every secret it sends is
// handed to the dialer bound to the host of the endpoint recorded with it.
//
// This package and internal/carry are the only callers of Sealer.Open: it
// opens a refresh token to trade it, a verifier to send it, a client secret
// to authenticate, and a credential to revoke it.
package signin

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// The times of specs/007-sign-in.md, one constant each.
const (
	// FlowTime is how long a flow waits for its callback.
	FlowTime = 10 * time.Minute
	// ConfirmTime is how long a flow waits for its confirm after the
	// callback.
	ConfirmTime = 2 * time.Minute
	// tokenTimeout bounds a request to a token endpoint.
	tokenTimeout = 15 * time.Second
	// RefreshAhead is how long before its expiry an access token is
	// refreshed.
	RefreshAhead = 60 * time.Second
	// refreshLease is the lease a refresh claims, longer than its request.
	refreshLease = 30 * time.Second
	// refreshWait and refreshPoll are how long a caller that did not claim
	// waits for the version to change, and how often it reads it.
	refreshWait = 10 * time.Second
	refreshPoll = 250 * time.Millisecond
	// mintedFor is how long a minted token whose answer gave no lifetime is
	// kept.
	mintedFor = 5 * time.Minute
	// revokeTimeout bounds a revocation.
	revokeTimeout = 10 * time.Second
	// SweepEvery is how often a replica sweeps the flows that ran out.
	SweepEvery = time.Minute
	// sweepBatch is how many flows one sweep takes at once.
	sweepBatch = 100
)

// Connector is a connector as the sign-in reads it: the entry, and the url
// of a connector added by its address, which a credential of it is bound
// to, with what its add found and its sealed client secret.
type Connector struct {
	catalog.Connector
	// Ref is the connector reference: a catalog name, or an added
	// connector's id.
	Ref string
	// AddedURL is the url of a connector added by its address, and empty
	// for a catalog connector.
	AddedURL string
	// Found is what the add found of how the server signs people in.
	Found Found
	// ClientSecret is the sealed secret of a vouched-for added connector's
	// own client, bound to its id and Found's token endpoint.
	ClientSecret store.Sealed
	// Disabled is an added connector its owner turned off.
	Disabled bool
}

// ErrNoConnector is a reference that names no connector.
var ErrNoConnector = errors.New("signin: no connector")

// Signin is the sign-in of one process.
type Signin struct {
	Store  store.Store
	Sealer store.Sealer
	Dial   *dial.Client
	// Resolve finds the connector a reference names: ErrNoConnector for a
	// reference that names none.
	Resolve func(ctx context.Context, ref string) (Connector, error)
	// LookupEnv resolves a catalog secret's {env: NAME} reference at use.
	LookupEnv func(string) (string, bool)

	// PublicURL and BasePath make every address Pons hands out: the
	// redirect address and the client metadata documents.
	PublicURL string
	BasePath  string
	// ClientName and ClientURI are what a person reads of Pons on a
	// consent page.
	ClientName string
	ClientURI  string
	// ReturnURLs are where a browser may return to: exact URLs, and
	// prefixes that end in a slash.
	ReturnURLs []string

	Log *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// IDs makes identifiers; nil is id.Default.
	IDs *id.Generator

	// wait and poll are refreshWait and refreshPoll, which a test
	// shortens.
	wait, poll time.Duration

	mint mints
}

func (s *Signin) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Signin) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Signin) newID(prefix string) string {
	if s.IDs != nil {
		return s.IDs.New(prefix)
	}
	return id.New(prefix)
}

func (s *Signin) waits() (time.Duration, time.Duration) {
	w, p := s.wait, s.poll
	if w <= 0 {
		w = refreshWait
	}
	if p <= 0 {
		p = refreshPoll
	}
	return w, p
}

// RedirectURI is the one address Pons gives every authorization server.
func (s *Signin) RedirectURI() string { return s.PublicURL + s.BasePath + "/callback" }

// ClientDocumentURL is the address of the client metadata document catalog
// connectors share, and of an added connector's own when id is given.
func (s *Signin) ClientDocumentURL(id string) string {
	u := s.PublicURL + s.BasePath + "/client"
	if id != "" {
		u += "/" + id
	}
	return u
}

// Opened is a connection's credential, opened for a call: the connection as
// stored when the call arrived, its connector, the plaintext, the meta kept
// beside it and the version the plaintext was read at.
type Opened struct {
	Connection store.Connection
	Connector  Connector
	Secrets    store.Secrets
	Meta       store.Meta
	Version    int64
}

// Open opens a connection's stored credential: store.ErrNotFound for a
// connection with none, and a 503 sealing_unavailable for one no listed key
// opens, which moves no state.
func Open(ctx context.Context, st store.Store, sealer store.Sealer, c store.Connection, conn Connector) (Opened, error) {
	sealed, version, err := st.Credentials().Get(ctx, c.ID)
	if err != nil {
		return Opened{}, err
	}
	meta, err := store.DecodeMeta(sealed.Meta)
	if err != nil {
		return Opened{}, apierr.Internal(err)
	}
	plain, err := sealer.Open(sealed.Sealed, store.CredentialBinding(c.ID, c.Owner, c.Auth, meta, conn.AddedURL))
	if err != nil {
		return Opened{}, &apierr.Error{Code: apierr.CodeSealingUnavailable, Reason: "not_opened"}
	}
	secrets, err := store.DecodeSecrets(plain)
	clear(plain)
	if err != nil {
		return Opened{}, apierr.Internal(err)
	}
	return Opened{Connection: c, Connector: conn, Secrets: secrets, Meta: meta, Version: version}, nil
}

// notConnected is the 409 a call answers when its connection cannot be
// used: its state, and the reason why.
func notConnected(state store.State, reason string) *apierr.Error {
	return &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: reason, Extra: map[string]any{"state": string(state)}}
}

// Refused moves a connection whose credential the other service refused:
// to needs_reconnect with the reason, or, for one pending for a reconnect,
// keeping its state and taking the reason so its confirm still applies. It
// answers the 409 the call gives, with the state the connection is in.
func Refused(ctx context.Context, st store.Store, c store.Connection, reason string) error {
	to := store.StateNeedsReconnect
	if c.State == store.StatePending {
		to = store.StatePending
	}
	err := st.Connections().Move(ctx, c.ID, c.State, to, reason)
	switch {
	case errors.Is(err, store.ErrIllegalMove), errors.Is(err, store.ErrStateMoved), errors.Is(err, store.ErrNotFound):
		// Another request moved it first, or it was never usable from its
		// state: the refusal stands either way.
	case err != nil:
		return apierr.Internal(err)
	}
	return notConnected(to, reason)
}

// mints are the tokens minted for client_credentials connections in this
// process, never stored.
type mints struct {
	mu     sync.Mutex
	tokens map[string]minted      // by connection and credential version
	locks  map[string]*sync.Mutex // one mint per connection at a time
}

type minted struct {
	token string
	until time.Time
}

// scopeList reads a space-separated scope member.
func scopeList(s string) []string { return strings.Fields(s) }
