---
title: "Connectors added for others: an owner the authorizer names, a connection to another owner's connector, edits without a restart, a vouched-for server with a registered client, and sign-in at the server an added connector names"
status: drafted
track: core
depends_on:
  - specs/003-api.md
  - specs/004-identity-and-authorization.md
  - specs/005-store-and-sealing.md
  - specs/006-catalog.md
  - specs/007-sign-in.md
  - specs/012-security-and-threat-model.md
affects: [catalog/, internal/httpapi/, internal/access/, internal/signin/, internal/store/, internal/carry/, api/openapi.yaml]
effort: large
created: 2026-10-15
updated: 2026-10-15
author: changkun
---

# Connectors added for others

## Overview

An installation offers outside services in two ways: the catalog file
its operator writes ([[006-catalog]]), and the MCP servers a person adds
by address with `POST /connectors`. Until now the second was a person's
alone: nobody else saw it, and an edit meant deleting it and adding it
again.

This spec lets an added connector be offered to others, with the
authorizer deciding to whom. An operator's administrator adds a server
that everyone may connect. An organization's administrators add one
that the organization's members may connect. A person adds their own,
as before. Each of these is changed and turned off through the API, and
none of them needs a restart.

It also finishes sign-in for an added connector ([[006-catalog]],
"Remains"). The person gives an address and nothing else. Pons asks the
server how to sign in, and identifies itself by a client metadata
document or, where the server takes only that, by dynamic registration.

## Current state

- **What an added connector holds.** It is a row in `connectors` with
  an owner, which the allow's `Limits.Owner` names
  (`httpapi/connectors.go`, `ownerOf`). The list reads the rows of the
  owners the allow's filter names (`owner = ANY($1)`), so an authorizer
  could already list one owner's connector to another.
- **What stops a connection to it.** A connect whose owner differs from
  the connector's is `404 connector_not_found`
  (`httpapi/connections.go`, "An added connector is its owner's alone").
- **What the routes allow.** There is no update route. `auth.client` is
  refused on an added connector (`catalog.Validate`), and so is
  `auth.type: oauth`: an add answers `422 sign_in_unsupported`.
- **Tool marks.** An added connector takes them, and a `tools/call`
  through it is held to them ([[008-carrying-a-call]]).

## Design

### Whose an added connector is

An added connector's `owner` is whatever the allow of its
`connector.create` names, as for any created object ([[004-identity-and-authorization]]).
Pons gives an owner no meaning. An authorizer chooses the owners it
needs: a person's subject, an organization's, and one that stands for
the whole installation. The owner policy Pons applies without an
authorizer is unchanged: a caller adds under its own subject only, and
sees its own.

Who sees an added connector is the authorizer's answer, as it is for a
catalog connector:

- `GET /connectors` lists the catalog, then the added connectors of
  every owner the allow's filter names. A filter that names a person,
  their organization and the installation's owner lists all three
  kinds in one answer.
- `connector.read` already sends the connector's `owner`. An allow is
  what makes another owner's connector readable; a deny remains `404`.

An owner holds at most `PONS_MAX_ADDED_CONNECTORS` added connectors
(default 50). One more is `409 connector_limit`, so a script that adds
in a loop fills one owner's list and nobody else's.

### A connection to another owner's connector

A connect no longer requires the connection's owner to equal the
connector's. In its place, the connector must be readable to the
caller: Pons asks `connector.read` before `connection.create`, and
answers `404 connector_not_found` on a deny, as before. The connection
still records its connector by id ([[002-objects]]), and its credential
stays its own owner's, sealed to that owner's row.

`connection.create` sends a new field, `connector_owner`, so an
authorizer can tell a connect to a person's own server from one to an
organization's or the installation's without a second question.

### Edits

`PATCH /connectors/{id}` changes an added connector in place. It asks
`connector.update`, a new action that sends `owner` and the id.

| Member | Changeable | Why |
|---|---|---|
| `title`, `description`, `icon` | yes | presentation |
| `tools.read_only`, `tools.hidden` | yes | the next call is held to the new marks |
| `auth.scopes` | yes | the next sign-in asks for them; a connection keeps what it was granted |
| `auth.client.secret` | yes, vouched-for only | a rotated secret is used at the next token request |
| `disabled` | yes | see below |
| `name`, `kind`, `url`, `auth.type`, `auth.client.id` | no: `400 immutable_field` | a connection binds its credential to `url` ([[005-store-and-sealing]]), and one whose `kind` or `auth.type` differs reads as gone ([[006-catalog]]). A changed address is a new connector |

A disabled connector stays listed with `disabled: true`, so its owner
can turn it back on. A connect to it is `409 connector_disabled`, and a
call through a connection to it is `409 connection_not_connected` with
`details.reason` `connector_disabled`. Its connections and their
credentials are kept, and turning it on makes them usable again. A
delete is still refused with `409 connector_in_use` while a connection
uses it: turning it off is how a server in use is withdrawn.

Every replica reads an added connector from the store at each request,
so an edit holds at the next request on every replica, and nothing is
restarted.

### A vouched-for server

A server an administrator adds for others has been looked at by
someone the installation trusts, and one a person adds has not. The
authorizer says which, with a new limit on the allow of
`connector.create`, `vouched: true`. Pons stores it with the connector,
shows it in the connector's view, and never sets it itself.

A vouched-for connector may carry one thing more than any added
connector: **a registered client.** `auth.client` takes `id`, and
`secret` as a value. Pons seals the secret in a new column of
`connectors`, `client_secret_sealed`, bound to the connector's id and
token endpoint ([[005-store-and-sealing]]), and never answers it. The
connector's view names the redirect address to register with that
client, which is the per-issuer address below when the server sends no
`iss`.

An add without `vouched` that carries `auth.client` stays
`400 unknown_field`. Vouching changes nothing else: the issuer rule
below is the same for every added server. An organization's
administrator vouches for a server to the organization, not to the
installation, so a vouched-for server is no more trusted to send the
person to the right authorization server than any other added one.

### Sign-in at the server an added connector names

`auth` becomes optional on an add. When it is left out, Pons asks the
server, at the address given, how to sign in, and stores the answer:

1. **An MCP `initialize` with no credential.** A success means
   `auth.type: none`.
2. **A `401` that names its protected resource metadata** (RFC 9728),
   in `WWW-Authenticate` or at the well-known address, means `oauth`
   with `discovery: resource`. Pons reads the metadata and that of the
   authorization server it names (RFC 8414) at the add, with the checks
   of [[007-sign-in]], and refuses the add with
   `422 sign_in_unsupported` when no way to identify itself is offered
   (below).
3. **A `401` or `403` with no metadata** means `token`, and the
   connector asks for a key at connect, with the hint "API key".
4. **Anything else** is `422 server_unreachable`, with the status or
   the failure in `details.reason`. The address is never echoed.

These requests go through the one dialer ([[009-outbound-requests]])
and count against the add's own rate limit, so an add cannot be used to
send requests faster than adds are allowed.

An add that names `auth` is checked against the same answer. One that
names `none` for a server that asks for sign-in is `422 auth_mismatch`.

For an added connector of type `oauth`, Pons identifies itself in this
order:

1. **A registered client**, on a vouched-for connector alone.
2. **The connector's client metadata document**, when the
   authorization server's metadata sets
   `client_id_metadata_document_supported`, as today.
3. **Dynamic registration** (RFC 7591), when the metadata has a
   `registration_endpoint`. This is the registration [[007-sign-in]]
   already makes for a catalog connector: kept by issuer and redirect
   address, its secret sealed, and reused by the next sign-in at that
   issuer. The difference is that a consent at the server is then the
   installation's and not the connector's, so a second connector at
   the same server may reuse it. The connector's view says
   `client: registered` so a person can tell.
4. **Otherwise** `422 sign_in_unsupported`.

#### The issuer rule without `iss`

An added server whose authorization server does not say it sends `iss`
was refused until now (RFC 9700, section 4.4). It is accepted with the
other defense the RFC names: a redirect address of its own. This holds
for every added server, vouched for or not.
Its sign-ins use `{PONS_PUBLIC_URL}{base}/callback/{key}`, where `key`
is the first 16 hex digits of the SHA-256 of the issuer. The callback
compares `key` with the flow's recorded issuer before the code goes
anywhere, so an answer that arrives at another server's address is
refused. The client metadata document and a registration name that
address. A server that sends `iss` keeps the shared callback.

### A connection's tools

`GET /connections/{id}/tools` answers the connector's `tools/list`
through that connection: each tool's name, description and the effect
its marks give it. It asks `connection.read`, so the owner reads it,
and it records no call. An administrator uses it to choose tool marks
from the tools a server really has.

## Decisions

| Decision | Why | Not chosen |
|---|---|---|
| The owner stays an opaque string, chosen by the authorizer | Pons reads no claim for meaning ([[004-identity-and-authorization]]). An organization and an installation are an authorizer's ideas | An `installation` or `organization` owner kind in Pons: a second notion of identity beside the authorizer's |
| Readability replaces equal owners at connect | Who may connect what is a policy question, and an authorizer already answers `connector.read` | A list of admitted owners in Pons's configuration: a policy outside the authorizer |
| Edits keep `url` fixed | A credential is bound to it, and a changed address is another server | Rebinding every credential at an edit: one wrong address sends every credential somewhere new |
| Turning off, not deleting, a connector in use | Connections and credentials survive a mistake, and nothing reconnects | Deleting with its connections: one click loses every person's sign-in |
| `vouched` is the authorizer's to set, and unlocks a registered client alone | Who has looked at a server is the installation's knowledge. An organization's administrator vouches to the organization, so vouching cannot also stand in for the mix-up defense | Vouching by the owner's kind: Pons would read meaning into an owner. Accepting a missing `iss` from a vouched-for server: a hostile organization server could receive another server's answer at the shared callback |
| Dynamic registration for added servers | Many MCP servers take no client metadata document yet, and an address alone must be enough | The document alone: most servers could not be added |
| A redirect address per issuer when `iss` is missing | RFC 9700 names it as the alternative defense, and many servers send no `iss` | Refusing those servers: the add a person expects would fail for reasons they cannot see |

## Not in this spec

- **Who an installation lets add what, and for whom.** That is the
  authorizer's.
- **A catalog entry made editable.** The file stays the operator's,
  reviewed and read at start.
- **A server of kind `http` added through the API.** Its paths and
  headers stay the operator's to judge ([[006-catalog]]).
- **A tool list kept by Pons.** Pons asks the server each time.

## Acceptance criteria

| Criterion | Test |
|---|---|
| An add whose allow names another owner stores that owner, and the list shows the connector to every owner the filter names and to no other | `TestAnAddedConnectorListsToTheOwnersTheFilterNames` |
| An owner's add past `PONS_MAX_ADDED_CONNECTORS` is `409 connector_limit`, and another owner's add still succeeds | `TestAnOwnerHoldsAtMostItsLimitOfConnectors` |
| A connect to another owner's connector succeeds when `connector.read` allows it, sends `connector_owner`, and is `404` when it denies | `TestAConnectionToAnotherOwnersConnector` |
| `PATCH` changes each changeable member, answers `400 immutable_field` for the others, and asks `connector.update` | `TestAnEditChangesWhatMayChange` |
| A changed tool mark holds the next call on a second replica with no restart | `TestAnEditHoldsTheNextCallOnEveryReplica` |
| A disabled connector refuses a connect and a call with its reasons, keeps its connections and their credentials, and serves them again when turned on | `TestTurningAConnectorOffAndOn` |
| `auth.client` is taken only with `vouched`, its secret is sealed, bound to its row, and never answered; vouching changes no other rule | `TestOnlyAVouchedForConnectorTakesAClient`, `store.TestAConnectorsSecretIsSealed` |
| An add without `auth` stores `none`, `oauth` or `token` from the server's answer, and refuses an unreachable server without echoing its address | `TestAnAddAsksTheServerHowToSignIn` |
| An added `oauth` connector signs in by a registered client, a client metadata document or a registration, in that order | `signin.TestAnAddedConnectorIdentifiesItself` |
| An added server without `iss`, vouched for or not, signs in at its own callback address, and an answer at another issuer's address is refused | `signin.TestACallbackOfItsOwnPerIssuer` |
| `GET /connections/{id}/tools` answers the tools with their effects to the owner, and is `404` to anyone else | `TestAConnectionsTools` |

## Implementation status

Drafted. Nothing is built.
