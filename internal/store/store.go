// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package store is the contract of specs/005-store-and-sealing.md: every
// fact Pons must not lose, behind one interface with two adapters, the
// memory store of internal/store/memory and the Postgres store of
// internal/store/postgres, held to one suite in internal/store/storetest.
//
// A credential reaches an adapter sealed and leaves it sealed. No adapter
// is handed a Sealer, so neither can open what it holds; Sealer.Open is
// called by the code that places a credential in a request and by nothing
// else.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// The errors an adapter answers with. A handler maps each to the error of
// its route; none carries a value of the row.
var (
	// ErrNotFound is a row that does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrNameTaken is a name the owner already holds.
	ErrNameTaken = errors.New("store: the owner holds that name")
	// ErrLimitReached is a connection past its owner's cap.
	ErrLimitReached = errors.New("store: the owner holds as many connections as the cap allows")
	// ErrIllegalMove is a pair of states that is not an edge of the
	// connection's state machine. It is answered before any statement.
	ErrIllegalMove = errors.New("store: the move is not an edge of the state machine")
	// ErrStateMoved is a connection no longer in the state a move is from.
	ErrStateMoved = errors.New("store: the connection is no longer in that state")
	// ErrVersionMoved is a refresh that lost to a newer credential.
	ErrVersionMoved = errors.New("store: the credential's version moved")
	// ErrInUse is an added connector a connection still uses.
	ErrInUse = errors.New("store: a connection uses the connector")
	// ErrKeyTaken is an idempotency key the subject already used.
	ErrKeyTaken = errors.New("store: the idempotency key is taken")
)

// Store is the one store a server runs on.
type Store interface {
	// Tx runs fn in one transaction that commits all or nothing. An error
	// fn returns rolls it back and is returned.
	Tx(ctx context.Context, fn func(Tx) error) error
	// Tx is the same methods outside a transaction, each call its own.
	Tx
	// Ready answers whether the store can serve, within its own bound.
	Ready(ctx context.Context) error
	// Close releases what the store holds.
	Close() error
}

// Tx is every table, inside or outside a transaction.
type Tx interface {
	Connectors() Connectors // the connectors a person added
	Connections() Connections
	Credentials() Credentials
	Flows() Flows
	Registrations() Registrations
	Calls() Calls
	Idempotency() Idempotency
	Rotation() Rotation // the sealed values of every table, by key
}

// State is a connection's state.
type State string

// The states of specs/002-objects.md.
const (
	StatePending        State = "pending"
	StateConnected      State = "connected"
	StateNeedsReconnect State = "needs_reconnect"
)

// The reasons a credential stopped working.
const (
	ReasonRefreshRefused    = "refresh_refused"
	ReasonRevoked           = "revoked"
	ReasonCredentialRefused = "credential_refused"
)

// Edges are the moves of the connection's state machine, the diagram of
// specs/002-objects.md, as from and to. Delete, the edge to the end from
// every state, is Connections.Delete and not a move.
var Edges = [][2]State{
	{StatePending, StateConnected},
	{StatePending, StatePending},
	{StatePending, StateNeedsReconnect},
	{StateConnected, StateNeedsReconnect},
	{StateConnected, StatePending},
	{StateNeedsReconnect, StatePending},
	{StateNeedsReconnect, StateConnected},
}

// Legal reports whether from to is an edge.
func Legal(from, to State) bool {
	for _, e := range Edges {
		if e[0] == from && e[1] == to {
			return true
		}
	}
	return false
}

// Connector is a connector a person added (specs/006-catalog.md). A
// catalog connector has no row.
type Connector struct {
	ID          string
	Owner       string
	Name        string
	Title       string
	Description string
	Icon        string
	Kind        string
	URL         string
	Hosts       []string
	// Auth and Tools are the members of the connector's auth and tools,
	// as the catalog package encodes them.
	Auth      json.RawMessage
	Tools     json.RawMessage
	CreatedAt time.Time
}

// Connection is one owner's link to one connector (specs/002-objects.md).
// Its address and its marks are derived, not stored.
type Connection struct {
	ID        string
	Owner     string
	Name      string
	Connector string
	Kind      string
	Auth      string
	State     State
	Reason    string
	Account   string
	Scopes    []string
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
	// LastUsedAt and ExpiresAt are zero when unknown.
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// Account is what the other service says a connection acts as.
type Account struct {
	Account   string
	Scopes    []string
	ExpiresAt time.Time // zero when unknown
}

// Filter narrows a list of connections. Owners is the owners whose
// connections are listed, and an empty Owners lists none. Connector and
// State narrow further when set.
type Filter struct {
	Owners    []string
	Connector string
	State     State
}

// Page is one page of a list: at most Limit rows, newest first by id, after
// the id Cursor names. An empty Cursor starts at the newest.
type Page struct {
	Limit  int
	Cursor string
}

// Connectors are the connectors people added.
type Connectors interface {
	// Create inserts an added connector: ErrNameTaken when its owner holds
	// one of that name.
	Create(ctx context.Context, c Connector) error
	// Get reads one by id: ErrNotFound.
	Get(ctx context.Context, id string) (Connector, error)
	// List is the connectors of the owners, newest first. An empty owners
	// lists none.
	List(ctx context.Context, owners []string, p Page) (cs []Connector, next string, err error)
	// Delete removes one: ErrNotFound, and ErrInUse while a connection
	// names it.
	Delete(ctx context.Context, id string) error
}

// Connections are the connections of every owner.
type Connections interface {
	// Create inserts a connection in StatePending or StateConnected:
	// ErrNameTaken, and ErrLimitReached when its owner holds max already.
	// max of 0 is no cap. The count and the insert are made under one
	// transaction-level lock on the owner.
	Create(ctx context.Context, c Connection, max int) error
	// Get reads one by id: ErrNotFound.
	Get(ctx context.Context, id string) (Connection, error)
	// List is one page of the connections the filter admits.
	List(ctx context.Context, f Filter, p Page) (cs []Connection, next string, err error)
	// Rename changes the name: ErrNotFound, ErrNameTaken.
	Rename(ctx context.Context, id, name string) error
	// Move changes the state from from to to, in one statement that
	// matches only while the row is in from: ErrIllegalMove before any
	// statement, ErrStateMoved when it no longer is, ErrNotFound. A move to
	// StateNeedsReconnect, and a move from StatePending to StatePending,
	// sets the reason; a move to StateConnected clears it; any other keeps
	// it.
	Move(ctx context.Context, id string, from, to State, reason string) error
	// Describe writes the account, the scopes and the expiry.
	Describe(ctx context.Context, id string, a Account) error
	// Touch writes last_used_at only when it is empty or more than a
	// minute behind at, in one statement that reads nothing.
	Touch(ctx context.Context, id string, at time.Time) error
	// Delete removes the connection with its credential and its flow, in
	// one transaction: ErrNotFound.
	Delete(ctx context.Context, id string) error
	// CountByState counts every owner's connections per state.
	CountByState(ctx context.Context) (map[State]int64, error)
	// InUse reports whether a connection names the connector reference.
	InUse(ctx context.Context, connector string) (bool, error)
}

// Credential kinds.
const (
	KindOAuth             = "oauth"
	KindToken             = "token"
	KindClientCredentials = "client_credentials"
)

// SealedCredential is a connection's credential as it is stored.
type SealedCredential struct {
	Kind   string          // oauth, token or client_credentials
	Meta   json.RawMessage // credentials.meta, in the clear
	Sealed Sealed
}

// Credentials are the sealed credentials of connections.
type Credentials interface {
	// Put writes the credential, adds one to its version and clears the
	// refresh lease. The first Put of a connection writes version 1.
	Put(ctx context.Context, connectionID string, c SealedCredential) (version int64, err error)
	// Get reads it: ErrNotFound.
	Get(ctx context.Context, connectionID string) (c SealedCredential, version int64, err error)
	// ClaimRefresh sets the lease to end lease from now when the row has
	// none or one that lapsed, judged by the store's clock, and reports
	// whether it did and the credential's version.
	ClaimRefresh(ctx context.Context, connectionID string, lease time.Duration) (claimed bool, version int64, err error)
	// CompleteRefresh writes the new credential, adds one to the version
	// and clears the lease, only while the version is fromVersion:
	// ErrVersionMoved otherwise, and nothing is written.
	CompleteRefresh(ctx context.Context, connectionID string, fromVersion int64, sealed SealedCredential) error
	// ReleaseRefresh clears the lease.
	ReleaseRefresh(ctx context.Context, connectionID string) error
}

// Flow is a sign-in in progress (specs/002-objects.md, specs/007-sign-in.md).
type Flow struct {
	ID                    string
	Connection            string
	StateHash             []byte // empty once the callback came
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RevocationEndpoint    string
	IssParameterSupported bool
	ClientID              string
	RedirectURI           string
	Resource              string
	Scopes                []string
	ReturnTo              string
	FinishHash            []byte // empty until the callback came
	Verifier              Sealed
	// Pending is the credential the callback received, not yet the
	// connection's; its Sealed is zero until then.
	Pending   SealedCredential
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Flows are the sign-ins in progress, at most one per connection.
type Flows interface {
	// Put writes a flow, replacing the live flow of its connection.
	Put(ctx context.Context, f Flow) error
	// Get reads the flow of a connection: ErrNotFound.
	Get(ctx context.Context, connectionID string) (Flow, error)
	// ByState reads the flow whose state hash is h: ErrNotFound.
	ByState(ctx context.Context, h []byte) (Flow, error)
	// Delete removes the flow of a connection.
	Delete(ctx context.Context, connectionID string) error
	// TakeExpired deletes and returns up to limit flows whose time is
	// before now, in one statement, so each reaches one sweeper.
	TakeExpired(ctx context.Context, now time.Time, limit int) ([]Flow, error)
}

// Registration is what an authorization server issued to Pons when Pons
// registered itself there.
type Registration struct {
	Issuer       string
	RedirectURI  string
	ClientID     string
	Secret       Sealed // zero when no secret was issued
	RegisteredAt time.Time
}

// Registrations are kept per issuer and redirect address.
type Registrations interface {
	// Put inserts a registration and answers the one stored: of two
	// replicas that register at once, the first row is kept.
	Put(ctx context.Context, r Registration) (Registration, error)
	// Get reads one: ErrNotFound.
	Get(ctx context.Context, issuer, redirectURI string) (Registration, error)
	// Delete removes one.
	Delete(ctx context.Context, issuer, redirectURI string) error
}

// Call is a record that a call happened (specs/002-objects.md). No field
// holds an argument, a result, a header or a query string.
type Call struct {
	ID         string
	Connection string
	Owner      string
	Connector  string
	Subject    string
	Session    string
	At         time.Time
	DurationMS int64
	Method     string
	Tool       string
	Effect     string
	Outcome    string
	Status     int // 0 when the connector did not answer
	BytesIn    int64
	BytesOut   int64
}

// Calls are the call records.
type Calls interface {
	// Insert writes one record.
	Insert(ctx context.Context, c Call) error
	// List is one page of a connection's records, newest first.
	List(ctx context.Context, connectionID string, p Page) (cs []Call, next string, err error)
	// Prune deletes up to limit records older than before and says how
	// many.
	Prune(ctx context.Context, before time.Time, limit int) (int, error)
}

// IdempotencyKey is the row a create writes with the object it makes.
type IdempotencyKey struct {
	Subject   string
	Key       string
	Route     string
	Status    int
	Object    string // the id of the object the create made
	CreatedAt time.Time
}

// Idempotency are the idempotency keys of creates.
type Idempotency interface {
	// Put inserts a key: ErrKeyTaken when the subject used it already.
	Put(ctx context.Context, k IdempotencyKey) error
	// Get reads one: ErrNotFound.
	Get(ctx context.Context, subject, key string) (IdempotencyKey, error)
	// Prune deletes up to limit keys older than before and says how many.
	Prune(ctx context.Context, before time.Time, limit int) (int, error)
}

// The tables whose rows hold sealed values, as Rotation names them.
const (
	TableCredentials   = "credentials"
	TableFlows         = "flows"
	TableRegistrations = "registrations"
)

// SealedTables lists them in the order a rotation walks them.
var SealedTables = []string{TableCredentials, TableFlows, TableRegistrations}

// Rotation reads and rewrites the sealed values of every table by key.
type Rotation interface {
	// RewrapBatch rewraps the sealed values of up to limit rows of table
	// that are under a listed key other than the first, in one transaction
	// that locks its rows and skips rows another replica holds; n is how
	// many.
	RewrapBatch(ctx context.Context, table string, keys KeyIDs, limit int, rewrap func(Sealed) (Sealed, error)) (n int, err error)
	// CountNotFirst counts, per table, the sealed values not under the
	// first key.
	CountNotFirst(ctx context.Context, keys KeyIDs) (map[string]KeyCount, error)
}

// KeyIDs names the sealing keys.
type KeyIDs struct {
	First  []byte   // the id of the key that wraps
	Listed [][]byte // the id of every listed key, the first included
}

// KeyCount is what remains of a rotation in one table.
type KeyCount struct {
	NotFirst int64 // under a listed key other than the first: what a rewrap has left
	NoKey    int64 // under no listed key: what ponsd check fails on
}
