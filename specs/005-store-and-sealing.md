---
title: "Store and sealing: the tables, the two adapters and their one suite, envelope encryption, key rotation"
status: drafted
track: core
depends_on:
  - specs/001-architecture.md
  - specs/002-objects.md
affects: [internal/store/, internal/config/, cmd/ponsd/]
effort: large
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Store and sealing

## Overview

Every fact Pons must not lose is in one store: added connectors,
connections, credentials as ciphertext, flows, registrations, call
records and idempotency keys. This spec fixes its contract, tables, two
adapters and their one suite; how a credential is sealed, bound to its
row, under a key only Pons holds and rotated with no downtime; and the
three primitives that make a refresh the work of one writer.

## Current state

Nothing is built.

A sandbox control plane in a sibling project has one store contract
with a memory and a Postgres adapter under one suite, and seals each
secret under a data key of its own, wrapped in a column apart so a
rotation leaves the value untouched. An agent runtime adds the key
list, the background rewrap and the check that reports what remains. A
document parsing service runs behind a transaction-mode pooler. Pons
adds a ciphertext bound to its row, and a refresh lease in a column.

## Design

### The contract

```go
type Store interface {
    Tx(ctx context.Context, fn func(Tx) error) error // commits all or nothing
    Tx // the same methods outside a transaction, each call its own
    Ready(ctx context.Context) error
    Close() error
}

type Tx interface {
    Connectors() Connectors // the connectors a person added
    Connections() Connections
    Credentials() Credentials
    Flows() Flows
    Registrations() Registrations
    Calls() Calls
    Idempotency() Idempotency
}

type Connections interface {
    Create(ctx context.Context, c Connection, max int) error // ErrNameTaken; ErrLimitReached at max, 0 is no cap
    Get(ctx context.Context, id string) (Connection, error)  // ErrNotFound
    List(ctx context.Context, f Filter, p Page) (cs []Connection, next string, err error)
    Rename(ctx context.Context, id, name string) error
    Move(ctx context.Context, id string, from, to State, reason string) error // ErrIllegalMove, ErrStateMoved
    Describe(ctx context.Context, id string, a Account) error // account, scopes, expires_at
    Touch(ctx context.Context, id string, at time.Time) error // last_used_at
    Delete(ctx context.Context, id string) error              // with its credential and its flow
}

type Credentials interface {
    Put(ctx context.Context, connectionID string, c SealedCredential) (version int64, err error)
    Get(ctx context.Context, connectionID string) (c SealedCredential, version int64, err error)
    ClaimRefresh(ctx context.Context, connectionID string, until time.Time) (claimed bool, version int64, err error)
    CompleteRefresh(ctx context.Context, connectionID string, fromVersion int64, sealed SealedCredential) error
    ReleaseRefresh(ctx context.Context, connectionID string) error
}
```

The other five are the plain accessors of their tables, with
`Prune(ctx, before, limit)` on `Calls` and `Idempotency`.
`Flows().Put` replaces the live flow of its connection, and
`Flows().TakeExpired(ctx, now, limit)` deletes and returns flows past
their time in one statement, so each reaches one sweeper
([[007-sign-in]]). `Filter` is `Owners`, `Connector` and `State`;
`Page` is `Limit` and `Cursor`, newest first by id ([[003-api]]).

The contract and the sealing live in `internal/store`, the adapters in
`internal/store/postgres` and `internal/store/memory`, and one suite
with a case per method in `internal/store/storetest`. The memory
adapter is exempt only from durability and the schema checks.

### Tables

Ids and subjects are `text`, times `timestamptz`, hashes and sealed
columns `bytea`, and the columns marked json `jsonb`.

| Table | Columns | Keys and indexes |
|---|---|---|
| `connectors` | `id`, `owner`, `name`, `title`, `description`, `icon`, `kind`, `url`, `hosts` json, `auth` json, `tools` json, `created_at` | primary `id`; unique `(owner, name)` |
| `connections` | `id`, `owner`, `name`, `connector`, `kind`, `auth`, `state`, `reason`, `account`, `scopes` json, `created_by`, `created_at`, `updated_at`, `last_used_at`, `expires_at` | primary `id`; unique `(owner, name)`; `(owner, id)` for a list; `(connector)` for `connector_in_use` |
| `credentials` | `connection`, `kind`, `meta` json, the five sealed columns, `version`, `refresh_until`, `updated_at` | primary `connection`, a foreign key that cascades |
| `flows` | `id`, `connection`, `state_hash`, `issuer`, `authorization_endpoint`, `token_endpoint`, `client_id`, `redirect_uri`, `resource`, `scopes` json, `return_to`, `finish_hash`, `pending_kind`, `pending_meta` json, `created_at`, `expires_at`, and the five sealed columns twice, prefixed `verifier_` and `pending_` | primary `id`; unique `connection`, a foreign key that cascades; unique `state_hash`; `(expires_at)` |
| `registrations` | `issuer`, `redirect_uri`, `client_id`, `registered_at`, and the five sealed columns prefixed `secret_`, null when no secret was issued | primary `(issuer, redirect_uri)` |
| `calls` | `id`, `connection`, `owner`, `connector`, `subject`, `session`, `at`, `duration_ms`, `method`, `tool`, `effect`, `outcome`, `status`, `bytes_in`, `bytes_out` | primary `id`; `(connection, id)` for a list; `(at)` for the sweep; no foreign key |
| `idempotency_keys` | `subject`, `key`, `route`, `status`, `object`, `created_at` | primary `(subject, key)`; `(created_at)` |

The five sealed columns are `key_id`, `wrapped_key`, `key_nonce`,
`ciphertext` and `nonce`. `credentials.meta` is what [[002-objects]]
keeps in the clear beside a credential of its kind; `version` starts at
1. A connection's `address` and `tools` are derived, not stored, and a
catalog connector has no row ([[006-catalog]]).

### Connection state

`Create` admits `pending` and `connected` alone. `Move` changes the
state in one statement that matches only while the row is in `from`. A
pair that is not an edge of the diagram in [[002-objects]] is
`ErrIllegalMove` before any statement runs, from one Go table of edges
both adapters read; a row no longer in `from` is `ErrStateMoved`.
`reason` is set by a move to `needs_reconnect`, kept through a
reconnect, and cleared by a move to `connected`.

`Delete`, the edge to the end from any state, removes the connection,
its credential and its flow in one transaction, with cascading foreign
keys, so no path leaves a ciphertext without its connection. `Create`
with a cap counts the owner's connections and inserts under one
transaction-level lock on the owner, so two creates at one remaining
place yield one connection ([[004-identity-and-authorization]]).

### Sealing

```go
type Sealed struct { // one sealed value, as its five columns
    KeyID      []byte // 8 bytes: the sealing key that wrapped the data key
    WrappedKey []byte // the data key, sealed under that key
    KeyNonce   []byte // 12 bytes
    Ciphertext []byte // the value, sealed under the data key
    Nonce      []byte // 12 bytes
}

type SealedCredential struct {
    Kind   string          // oauth, token or client_credentials
    Meta   json.RawMessage // credentials.meta, in the clear
    Sealed Sealed
}

type Binding []string // what a sealed value is tied to: its additional data

type Sealer interface {
    Seal(plaintext []byte, b Binding) (Sealed, error) // ErrNoSealingKey
    Open(s Sealed, b Binding) ([]byte, error)         // ErrNotOpened
    Rewrap(s Sealed) (Sealed, error)                  // the data key under the first key
}
```

A fresh random 32-byte data key seals the value with AES-256-GCM under
a random 96-bit nonce, with the binding as additional data. The data
key is then wrapped with AES-256-GCM, under a nonce of its own, by the
first key of `PONS_SEALING_KEYS`, and stored with that key's id: the
first 8 bytes of the SHA-256 of its 32 bytes. Every version of a
credential has a data key of its own: a refresh, a reconnect and a
replaced key each seal anew. A credential's plaintext is one JSON
document of the members [[002-objects]] lists as sealed for its kind.

| Sealed value | Binding |
|---|---|
| a connection's credential | `credential`, the connection id, the owner, the credential kind |
| a flow's pending credential | the same four, of the connection it is for |
| a flow's proof-key verifier | `verifier`, the flow id, the connection id |
| a registration's client secret | `registration`, the issuer, the redirect address |

Each member of a binding is written as its length in 4 bytes and its
bytes, so no two bindings share an encoding. A ciphertext copied to
another connection, another owner, another kind, or from a verifier's
columns into a credential's does not open. The wrap carries no
additional data, which is what lets a rotation rewrite the wrapped key
and nothing else. A pending credential carries the binding of the
credential it becomes, so a confirm moves ciphertext and opens nothing.

### Keys

`PONS_SEALING_KEYS` is a comma list of keys, each 32 bytes in base64,
standard or URL alphabet, padded or not. The first key wraps. Opening
tries the key whose id matches the row's, then every other key. A
malformed entry or a key listed twice stops the start, naming the
entry's position and never its value.

With a database configured, an empty list stops the start
([[011-distribution]]). On the memory store the server starts, says so
in its start-up log, and is not ready
([[010-records-and-observability]]); every request that would seal or
open answers `503 sealing_unavailable`, and reads, lists, deletes and a
connection whose `auth` is `none` are served. A value no listed key
opens, or whose binding does not match, answers the same `503` and is
logged with the row's id and key id alone. The key is missing, not the
credential, so the connection's state does not move.

### Rotation

Rotation is prepending a key and restarting. `serve` then rewraps in
the background, 100 rows at a time, the sealed values of
`credentials`, `flows` and `registrations` not under the first key.
Each batch is one short transaction that locks its rows and skips rows
another replica holds, so replicas share the work and a refresh waits
one batch at most. `Rewrap` reads no ciphertext, so no plaintext exists
during a rotation. A row under no listed key is skipped and counted.
`ponsd check` reports both figures per table and exits non-zero while
the second is not zero. An old key is removed once the first is zero.

### Who may open

`Sealer.Open` is the only method that returns a plaintext. Its only
callers are `internal/signin`, which trades a refresh token, a client
secret or a verifier, and `internal/carry`, which places a credential
in a forwarded request; a test over the call sites holds both. No
adapter is handed a `Sealer`, so neither can open what it holds.

### Refresh by one writer

[[007-sign-in]] decides when a refresh is due and what an answer means.
The store gives it three primitives over one column, `refresh_until`.

- `ClaimRefresh(ctx, connectionID, until)` sets the lease to `until`
  when the row has none or one that has lapsed, in one short statement,
  and returns whether it did and the credential's `version`. Lapse is
  judged by the store's clock, the database's in Postgres.
- `CompleteRefresh(ctx, connectionID, fromVersion, sealed)` writes the
  new credential, adds one to `version` and clears the lease, in one
  statement that matches only while `version` is still `fromVersion`.
  Otherwise it writes nothing and returns `ErrVersionMoved`: a
  reconnect or a replaced key got there first.
- `ReleaseRefresh(ctx, connectionID)` clears the lease after a failure,
  so the next caller may try at once.

`Put`, which a confirm and a replaced key use, also adds one to
`version` and clears the lease. The lease names no holder, so a writer
sets `until` past the deadline of its own request to the other service,
and one that fails after its lease lapsed leaves the column alone.

No database transaction is open while the other service is asked: the
claim, the request and the completion are three steps, and a replica
that dies between them leaves a lease that lapses by itself. No
session-level advisory lock is used, here or anywhere.

### Small writes and sweeps

`Touch` is one conditional statement that reads nothing: it writes
`last_used_at` only when the column is empty or more than a minute
behind. A replica also remembers when it last touched a connection, so
most calls send no statement.

A create writes its idempotency row in the transaction that makes the
object. A second request with the pair loses on the primary key and is
rendered from the stored object with the first status. The row holds no
body and no hash of one: a request may carry a key, and a create by
sign-in answers with the flow's `state`, kept only as a hash
([[002-objects]]). Its replay, while `pending`, therefore answers with
a new flow, as a reconnect does. A failed create leaves no row.

`Prune` deletes rows older than a time, at most `limit` at once, and
may run on every replica together; the ticker is
[[010-records-and-observability]]'s. `calls` has no foreign key, so a
record outlives its connection until its retention passes.

### Memory

What runs when `PONS_DATABASE_URL` is unset, for development and tests:
maps under one mutex, which is `Tx`. Nothing survives the process, and
the first log line says so. It runs the same edges, leases and sealed
values as Postgres, on a clock a test can move.

### Postgres

Selected by `PONS_DATABASE_URL`, through pgx. Migrations are embedded
under `internal/store/postgres/migrations` and applied at start through
`latere.ai/x/pkg/pgxmigrate.Up`. A schema version above the highest
embedded one stops the start, naming both; so does a dirty flag, naming
the version, and a database that cannot be reached
([[001-architecture]]). `Ready` is `SELECT 1` within 1 second.

A transaction-mode pooler may sit in front of Postgres, so nothing
depends on session state: no `LISTEN` or `NOTIFY`, no session advisory
lock, no named prepared statement. The store describes the unnamed
statement and caches the description in the client, unless the URL
names another query mode, and binds JSON as text. The one advisory
lock is the transaction-level one of a capped create. The migrator
holds a session lock, so migrations take `PONS_DATABASE_URL`, a direct
address, and the serving pool opens `PONS_DATABASE_POOL_URL` when it is
set, sized by its `pool_max_conns`.

## Not in this spec

A refresh's timing and a flow's steps ([[007-sign-in]]). The sweeps'
schedule ([[010-records-and-observability]]). The catalog, a file
([[006-catalog]]). A key service outside the process. Backups.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| Both adapters pass one suite over every method of every interface, and Postgres passes it on a direct connection and through a transaction-mode pooler | `TestMemoryStore`, `TestPostgresStore` and `TestPostgresStoreThroughAPooler`, over one `storetest` suite |
| Writes inside `Tx` commit together or not at all: a connection, its credential and its idempotency row, under a failure injected between them | the `Transactions` case of the suite |
| The connection's state moves only along the edges of the diagram, every other move is refused, and of two movers from one state one wins | `store.TestConnectionStateMachine`, run against both adapters |
| `(owner, name)` is unique, and 8 creates racing at one remaining place under a cap yield one connection | the `Names` and `Cap` cases of the suite |
| A delete removes the connection, its credential and its flow in one transaction | `TestDeleteRemovesTheCredentialFirst`, the `Delete` case of the suite |
| A sealed value opens under its binding alone: copied to another connection, owner or kind, or from a verifier into a credential, it does not open; two seals of one value share no column | `store.TestACopiedCiphertextDoesNotOpen`, `store.TestEverySealIsFresh` |
| A canary credential, verifier and client secret appear in no column of any table of either adapter | `TestNoPlaintextAtRest`, over a dump of Postgres and the memory store's maps |
| `Sealer.Open` is the only method that returns a plaintext, its only callers are `internal/signin` and `internal/carry`, and no adapter holds a `Sealer` | `TestOpenIsConfined`, over the parsed call sites |
| The first key wraps, every listed key opens, a key's id is the first 8 bytes of its SHA-256, and a malformed or repeated entry stops the start and prints no key | `store.TestTheKeyList`, `TestAMalformedKeyStopsTheStart` |
| After a key is prepended, the rewrap moves every value of the three tables under it and keeps every ciphertext byte; a refresh during it loses no write; `ponsd check` reports what remains and exits non-zero for a value under no key | `TestRotationRewrapsEveryValue`, `TestRewrapNeverOverwritesARefresh`, `TestCheckReportsWhatRemains` |
| With no sealing key a server over a database does not start; one on the memory store starts, says so, answers `503 sealing_unavailable` to every request that would seal or open, and serves reads and deletes; a value no key opens answers the same and moves no state | `TestWithoutASealingKey`, `TestAValueNoKeyOpens` |
| The flow sweep of two replicas takes each expired flow once | the `Flows` case of the suite |
| Of 16 callers that claim one refresh at once, one claims; a lapsed lease is claimed again; a release frees it; a completion on a moved version writes nothing; `Put` bumps the version and clears the lease | the `Refresh` case of the suite, `TestAReconnectWinsOverARefresh` |
| No transaction is open across the request to the other service: with a pool of one connection, a refresh held at the stub blocks no other statement | `TestNoTransactionSpansARefresh` |
| 100 calls through one connection within a minute write `last_used_at` once | `TestLastUsedIsWrittenOnceAMinute` |
| Two creates racing on one idempotency key make one object, and no row holds a body, a `state` or a hash of one; `Prune` removes only rows older than its time, at most its limit, each once | `TestIdempotentCreate`, the `Prune` case of the suite |
| A schema ahead of the binary and a dirty migration each stop the start, naming the version; no package outside `internal/store` imports the driver or the migrator | `TestSchemaGuards`, `TestDriverIsConfined` |
| With no database configured the server starts on the memory store and says so; with one configured and unreachable it does not start | `TestStoreSelection` |
