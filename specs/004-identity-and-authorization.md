---
title: "Identity and authorization: verifying a caller, the action vocabulary, the question to the authorizer, limits on an allow, the owner policy"
status: drafted
track: core
depends_on:
  - specs/001-architecture.md
  - specs/003-api.md
affects: [authorizer/, internal/access/, internal/httpapi/, internal/carry/]
effort: medium
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Identity and authorization

## Overview

Pons answers two questions about every request and decides neither
alone. Who is calling is settled by verifying a token against a
configured OpenID Connect issuer. What the caller may do is asked of an
authorizer, an HTTP endpoint the operator runs, which also returns the
limits the request is held to. With no authorizer configured, a
built-in policy lets a caller act on what it owns. Pons holds no
accounts, no roles and no plans.

Both are asked on every call as well, with the tool the call names, so
a caller's reach over a connection can be narrowed to single tools.

## Current state

Nothing is built.

The verifier and the authorizer contract are shared packages. A
document parsing service in a sibling project is the precedent for the
rest: a published vocabulary, limits on an allow, a deny answered as a
missing object, failing closed, and an owner policy. Pons adds an
action asked on every forwarded call.

## Design

### Verification

`latere.ai/x/pkg/authkit/jwt` verifies every bearer: signature against
the issuer's published keys, `iss` among `PONS_OIDC_ISSUERS`, `aud`
among `PONS_OIDC_AUDIENCE` (a comma list, the first entry primary,
`pons` when the variable is unset), `exp` and `nbf` with 30 seconds of
skew. A token that carries `iat` is also held to the verifier's age
bound of 24 hours. The subject is rendered once, by `authz.Subject`, as
`<iss>|<sub>`, and is what `owner`, `created_by`, a call record and the
authorizer request carry. Two issuers that agree on a `sub` are two
subjects.

A request with no bearer is `401 missing_token`. A bearer that is
refused is `401 invalid_token`, and its `details.reason` carries the
verifier's word for why, from `jwt.ReasonOf`: `audience`, `expired`,
`issuer`, `signature` and the others of its table. `retryable` is true
for `issuer_unavailable` alone. No part of a token is ever in an error
or a log line.

The verifier reads an issuer's discovery document and its key set,
through the operator client of [[009-outbound-requests]], and calls the
issuer for nothing else. `ponsd` warms it at start. An issuer that does
not answer then is named, the server starts, and the keys are read when
that issuer's first token arrives. A server that lists no issuer does
not start, and the error names the variable; the test tiers verify
against the stub issuer ([[011-distribution]]).

A token may carry grants: a personal access token is narrowed by its
holder to some actions on some resources, in the claim
`authorization_details`. The verifier is set to admit such a token
(`ReadsGrants`) and hands the grants on with every other claim. They
are applied where the decision is made: an authorizer built on
`latere.ai/x/pkg/authz/server` narrows its answer by them, and so does
the owner policy below.

Pons reads no claim for meaning: no role, no organization, no scope.
One claim is copied, for the record alone. A caller that is an agent's
session carries a `session` claim, and the call record keeps it
([[010-records-and-observability]]): the claim when it is a string, its
`id` member when it is an object, at most 128 bytes, and nothing when
it has another shape.

### The vocabulary

Published as Go constants in the public package `authorizer`, with
`Vocabulary()`, an `authz.Vocabulary` whose core is `pons`, for an
authorizer to validate against, and `Fields` for the members each
action sends.

| Kind | Action | Resource fields sent |
|---|---|---|
| `Connector` | `connector.list` | none |
| `Connector` | `connector.read` | `name` for a catalog connector; `id` and `owner` for an added one; `kind` |
| `Connector` | `connector.create` | `owner`, `kind`, `host` |
| `Connector` | `connector.delete` | `id`, `owner` |
| `Connection` | `connection.create` | `owner`, `connector`, `name`, `kind`, `auth`, and `id` when a confirm, a reconnect or a replaced key asks |
| `Connection` | `connection.read` | `id`, `owner`, `connector`, `name`, `kind`, `auth` |
| `Connection` | `connection.list` | none |
| `Connection` | `connection.update` | `id`, `owner`, `connector`, `name`, `kind`, `auth` |
| `Connection` | `connection.delete` | `id`, `owner`, `connector`, `name`, `kind`, `auth` |
| `Connection` | `connection.use` | `id`, `owner`, `connector`, `name`, `kind`, `method`, and `tool` and `effect` when the request names a tool, a path or a git service, and `refs` for a push ([[014-http-forwarding]]) |

A member Pons does not know for a request is left out, never sent
empty. `connector` is the connector reference of [[002-objects]]: a
catalog name or the id of an added connector. `host` is the host of the
address a person asks to add, so an authorizer can hold added
connectors to the domains it chooses. `method`, `tool` and `effect` are
the call record's members of those names. A catalog connector has no
owner, and its `connector.read` sends none.

On a create, `owner` is the owner the request names. A request may name
an owner other than the caller's subject: a service connecting for a
user, a member acting in an organization's space. The authorizer
decides whether the caller may. A request that names none leaves
`owner` out, which means: in the caller's context. Either way the allow
says whose the new object is, in its limits, so Pons reads no claim to
learn it.

`connection.create` is asked at four moments. A connect sends no `id`.
A confirm, a reconnect and a replaced key send the stored connection's
`id` and its fields, so the caller who confirms or gives a new
credential must be allowed to act for the owner the connection already
has ([[007-sign-in]]). An allow about a stored connection never moves
it to another owner.

`connection.use` is asked for every request to a connection's address
([[008-carrying-a-call]]), before the credential is opened.
`GET /callback`, `GET /client`, `GET /client/{id}` and
`GET /openapi.yaml` ask nothing: the callback is held by its `state`,
and the others are public documents.

### The question

The shared contract, `latere.ai/x/pkg/authz`: Pons posts the subject,
its issuer and `sub` apart, every verified claim verbatim, the action
and the resource, with a bearer of its own, and receives `{allow,
reason, ttl, limits, filter}`. The request also carries what is known
of the HTTP request: its id, the peer address and the user agent. Pons
fills no `workload` member.

The endpoint is `PONS_AUTHORIZER_URL`, asked through the operator
client. The bearer is the content of the file
`PONS_AUTHORIZER_TOKEN_FILE` names, read once at start and never
logged. A URL with no readable, non-empty token file stops the start,
naming the variable.

The client's rules are the contract's: an allow is cached for its `ttl`
(60 seconds when the answer names none, 600 at most), a deny for 5
seconds, unavailability never; one retry on a connection failure, and 5
seconds for the whole call. The cache is keyed by the whole question,
every claim and the peer included, so an allow of `connection.use` is
remembered per token, connection, method and tool, and a call of
another tool is asked. A change at the authorizer reaches a caller
within the `ttl` the authorizer chose. An answer about a resource with
no id is never cached, so every connect, add and list is asked.

`filter` narrows a list to owners. An allow with no filter lists the
caller's own, so an authorizer that lets a caller see other owners
names them. The request's `owner` member narrows further and never
widens. For `connector.list` the filter narrows the added connectors;
the catalog is the installation's and is listed whatever the filter. A
filter that names labels cannot be applied, since nothing in Pons is
labeled, and is treated as no answer.

### Denies and outages

A well-formed deny of a create or a list is `403 forbidden`, with the
authorizer's `reason` as `details.reason` and never in the sentence a
person reads.

A request about a stored object answers a deny the way it answers a
missing object, with the `404` of its kind, and carries nothing a
missing object's `404` does not. That covers a read, a change, a
delete, a use, a confirm and a reconnect. It holds for a subject that
may read the object and may not change it: a route asks one question,
and its deny does not say which it was.

An id that names nothing is `404` before any question is asked, so
during an outage an id that exists answers `503` and one that does not
answers `404`. This is accepted: an id carries 80 random bits, and
asking about unknown ids would let any caller drive the authorizer.

Anything that is not a well-formed answer is treated as unavailable:
another status than `200`, a body that does not parse or carries no
`allow`, no answer within the deadline, and limits or a filter that
cannot be read. The request then fails closed with `503
authorizer_unavailable`, with nothing done, and the error names neither
the endpoint nor its bearer.

### Limits

The limits on an allow are how an operator's plane tells Pons what this
caller is held to. Pons enforces what it is told and stores no plan.

```go
package authorizer

type Limits struct {
    Owner          string   // whose a created connection or connector is; empty is the caller's subject
    MaxConnections int      // connections one owner may hold; 0 leaves the installation's cap
    Connectors     []string // globs of connector references the caller may connect; empty is all
    ReadOnly       bool     // on a use: only tools whose effect is read
    Tools          []string // globs of tools the caller may call; empty is all
    Refs           []string // globs of full ref names a push may update; empty is all
    CallsPerMinute int      // per connection and subject; 0 is no cap
}
```

The JSON form has every member optional and exactly these keys:
`owner`, `max_connections`, `connectors`, `read_only`, `tools`,
`refs`, `calls_per_minute`. `DecodeLimits(authz.Decision)` reads it. An object
that does not parse, a key this version does not know, a figure below
zero and an empty glob make the answer no decision,
and the request fails closed with `503 authorizer_unavailable`: a
ceiling Pons cannot read is not one it can hold. Globs are those of the
catalog's tool marks ([[006-catalog]]).

| Member | Read from the allow of | Held |
|---|---|---|
| `owner` | `connection.create` with no `id`, `connector.create` | the create records it, and every question after carries it |
| `max_connections` | `connection.create` with no `id` | counted with the insert, under one lock on the owner ([[005-store-and-sealing]]): `403 forbidden` on `owner` |
| `connectors` | `connection.create` with no `id` | before anything is stored: `403 forbidden` on `connector` |
| `read_only` | `connection.use` | a `tools/call` whose effect is `write`: `403 forbidden` on `tool` |
| `tools` | `connection.use` | a `tools/call` of a tool no glob matches: `403 forbidden` on `tool` |
| `calls_per_minute` | `connection.use` | `429 rate_limited`, retryable |
| `refs` | `connection.use` | a push naming a ref no glob matches: `403 forbidden` on `refs` ([[014-http-forwarding]]) |

The limits of any other allow are not read. With no `owner` on the
allow, a create is recorded under the owner the request named, and
under the caller's subject when it named none. `connectors` is matched
against the connector reference, so a list of catalog names admits no
added connector, and `ctr_*` admits them all. A pending connection
counts toward `max_connections` until its flow expires. Each refusal's
`details.reason` names the limit and its figure, never the authorizer's
other answers.

A limit refuses a call after its allow, so the answer is a `403`, not a
`404`. A refused call opens no credential, reaches no connector, and is
recorded `denied`, at most once per subject and connection per minute
([[008-carrying-a-call]]). `read_only` and `tools` bind `tools/call`
alone; a list of tools is carried as it is ([[008-carrying-a-call]]).

`calls_per_minute` is counted per replica, in memory, with
`latere.ai/x/pkg/ratelimit`, so N replicas admit up to N times the
figure. It bounds a runaway caller and is no quota.

### The installation's limits

Four limits hold whatever the authorizer answers, and with no
authorizer at all. Each is a variable of [[011-distribution]].

| Variable | Default | Held |
|---|---|---|
| `PONS_MAX_CONNECTIONS_PER_OWNER` | 100 | as `max_connections`, under the same lock: `403 forbidden` on `owner` |
| `PONS_CREATES_PER_MINUTE` | 10 | per subject, over `POST /connectors`, `POST /connections` and a reconnect, each of which fetches discovery documents: `429 rate_limited`, retryable |
| `PONS_MAX_INFLIGHT_PER_SUBJECT` | 32 | requests of one subject in flight at connections' addresses ([[008-carrying-a-call]]): `429 rate_limited` |
| `PONS_MAX_INFLIGHT` | 1024 | requests in flight at connections' addresses in one process ([[008-carrying-a-call]]): `429 rate_limited` |

An allow's limits narrow these and never widen them: a
`max_connections` of 0, or above `PONS_MAX_CONNECTIONS_PER_OWNER`, is
held to the variable. Each refusal's `details.reason` names the limit
and its figure. The rate and the counts in flight are kept per replica,
in memory, as `calls_per_minute` is.

### The owner policy

With no `PONS_AUTHORIZER_URL`, `ponsd` logs `owner policy` at start and
decides itself. The rows, in the order they are tried:

| Question | Answer |
|---|---|
| the probe id, as any subject | deny, `probe` |
| no subject | deny, `anonymous` |
| an action outside the vocabulary, or asked about another kind | deny, `unknown_action` |
| `connector.read` of a catalog connector | allow |
| `connector.list`, `connection.list` | allow, with a filter that narrows the list to the subject's own |
| a stored connection or added connector whose owner is the subject, any action | allow |
| a create that names no owner, or names the subject | allow |
| anything else | deny, `not_owner` |

A caller creates under its own subject only; reads, uses, updates and
deletes the connections it owns; and sees the whole catalog and the
connectors it added. Naming another owner is denied for every subject,
so a service that connects for its users needs an authorizer. The
policy has no administrators and names no limit of its own: a use is
held to no tool list and no rate beyond the installation's limits
above. An allow is narrowed by the grants of the
caller's token, with `authz.Restrict`, as an authorizer's is, and a
token whose grants cannot be read is denied.

### What a handler depends on

Two interfaces of `internal/access`, and a handler cannot tell what is
behind either. One turns a request's bearer into a caller: the subject,
its issuer and `sub` apart, and every verified claim. The other answers
a question, an action and a resource, with a decision: allow or deny,
the reason, the limits in force, and the filter of a list. Every route
is written the same way: authenticate, build the resource from the
request and the stored object, ask, and act within the decision.

The routes are kept as data, one row per route of [[003-api]] with the
action and the fields it sends, held to the contract by a test.

At start `ponsd` sends the authorizer the contract's probe, a reserved
id every authorizer denies. An endpoint that allows it does not read
the request, and the server does not start. One that does not answer is
named and the server starts, since every request then fails closed.
`ponsd check` sends the same probe.

## Not in this spec

Browser sessions and cookies: a person reaches Pons only through a
client. An exchange endpoint: a service acting for a user authenticates
as itself and names the user as `owner`. Hiding a catalog connector
from one caller's list. Asking a person before a tool changes
something, which is the caller's ([[001-architecture]]). Deciding by a
call's arguments, which Pons does not read.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The verifier passes the shared conformance suite; a verified token becomes a caller whose subject is `<iss>\|<sub>` and whose claims are the token's, verbatim, and two issuers that agree on a `sub` are two subjects | `access.TestVerifierConformance`, which runs `authkit/conformance`; `access.TestAVerifiedTokenBecomesACaller` |
| A token for another audience, of an unlisted issuer, expired or not yet valid past the skew, or with a bad signature is `invalid_token` with the reason, and the error never repeats the token | `access.TestWhatTheVerifierRefuses`, `access.TestTheSkewOnExpAndNbf` |
| A server that lists no issuer does not start and names the variable; an authorizer URL with no token file does the same | `TestAServerWithNoIssuerIsRefused`, `TestAnAuthorizerNeedsItsTokenFile` |
| The constants of `authorizer` are the vocabulary table above, in its order with its fields, and the table of routes has one row per route of the contract, each asking the action of [[003-api]] | `authorizer.TestTheVocabularyIsTheSpecs`, `access.TestTheRowsAreTheSpecs` |
| Every route asks its action before it acts; a deny and an outage are answered with nothing done, over both stores | `httpapi.TestEveryRouteAsksItsAction`, `httpapi.TestADenyAndAnOutageAnswerBeforeAnythingIsDone` |
| The authorizer receives the subject, every claim verbatim, the action and the resource, and a use carries `tool` and `effect` when the request names a tool and neither when it does not | `access.TestTheEnvelopeCarriesTheCallerAndTheQuestion`, `carry.TestAUseAsksWithItsTool` |
| The endpoint Pons asks answers the contract for every row of the vocabulary | `access.TestAuthorizerConformance`, which runs `authz/conformance` against the stub authorizer |
| The client holds an allow for its `ttl`, a deny briefly and an outage never, asks a create and a list every time, and retries once on a connection failure | `access.TestWhatTheClientRemembers`, `access.TestACreateIsAlwaysAsked`, `access.TestOneRetryOnAConnectionFailure` |
| An allow of a use is remembered per tool: a second call of the same tool asks nothing within the `ttl`, a call of another tool asks, and a deny at the authorizer holds once the `ttl` has passed | `carry.TestAnAllowIsRememberedPerTool` |
| A deny of a read, a change, a delete, a use, a confirm and a reconnect is the `404` of its kind, byte for byte the answer of an id that names nothing; a deny of a create or a list is `403 forbidden` | `TestADenyDoesNotConfirmAnId` |
| Another status, a body with no `allow`, a late answer, limits with an unknown key, a negative figure or an empty glob, and a filter with labels are each `503 authorizer_unavailable` with nothing done | `access.TestTheClientFailsClosed`, `authorizer.TestDecodeRefusesWhatItCannotHold` |
| The limits object carries exactly the 7 keys above, and `DecodeLimits` reads back what an authorizer renders | `authorizer.TestTheWireNamesEveryMemberAndNoOther` |
| A create is recorded under the owner its allow names, else the owner the request named, else the caller's subject; a confirm and a reconnect do not move a connection to another owner | `TestWhoseACreateIs`, `TestAStoredConnectionKeepsItsOwner` |
| Each member of `Limits` has a case in which an allow carrying it changes the outcome of a request: the connection cap, a connector outside the globs, a writing tool under `read_only`, a tool outside `tools`, and the rate; a call a limit refuses opens no credential, reaches no connector and is recorded `denied` | `TestEachMemberOfAnAllowChangesTheOutcome`, a case per member, which fails when a member has none; `carry.TestALimitRefusesBeforeTheCredential` |
| With no authorizer, an owner's connection past `PONS_MAX_CONNECTIONS_PER_OWNER` is `403 forbidden` naming the limit, and a subject's create past `PONS_CREATES_PER_MINUTE` is `429 rate_limited`; under an authorizer, an allow's `max_connections` above the variable is held to it | `TestLimitsHoldWithNoAuthorizer` |
| A list is narrowed by its allow's filter and by the request's `owner`, and the catalog is listed whatever the filter | `TestAListIsNarrowedByItsAllowsFilter` |
| Under the owner policy a subject cannot read, list, use, rename, confirm or delete another subject's connection, cannot see another's added connector, and cannot create in another's name; with verified tokens of two owners against a running server, one reaches nothing of the other's | `access.TestTheOwnerPolicy`, `TestTheOwnerPolicyThroughTheAPI`, `TestAnotherOwnersTokenReachesNothing` |
| The owner policy answers the contract's conformance suite and narrows an allow by the grants of a token; it and the stub authorizer deny the probe id, and a server is refused an endpoint that allows it | `access.TestOwnerPolicyConformance`, `access.TestOwnerPolicyNarrowsByTheGrants`, `TestTheServerRefusesAnEndpointThatAllowsTheProbe` |
| The `session` claim reaches the authorizer verbatim and the call record as its id, and a claim of another shape or over 128 bytes leaves the record without one | `carry.TestTheSessionClaimIsCopiedNotRead` |
