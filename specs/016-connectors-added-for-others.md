---
title: "Connectors added for others: an owner the authorizer names, a connection to another owner's connector, edits without a restart, a vouched-for server with a registered client, and sign-in at the server an added connector names"
status: testing
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

Built on 2026-10-15; see Implementation status and Outcome. Before it,
an added connector was its owner's alone: a connect by another owner
was `404 connector_not_found`, no route changed one, `auth.client` was
refused, and an add of `auth.type` `oauth` answered `422
sign_in_unsupported`.

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

```json
GET /connections/{id}/tools
{ "items": [
  { "name": "get_note", "description": "Reads a note.", "effect": "read" },
  { "name": "delete_notebook", "description": "Deletes a notebook.", "effect": "write", "hidden": true } ] }
```

### How many connections use an added connector

An administrator's screen says "15 people connected" beside each server
and explains a removal by it. An added connector's view carries
`connections`, how many connections of every owner use it, to a caller
the authorizer lets change it, as it answers `connector.update`, and to
no other caller.

The count is asked as `connector.update`, the question an edit asks,
so an authorizer keeps one answer for who administers an owner's
servers. A read of one added connector asks it after `connector.read`,
with the id and the owner. A list asks it once for each owner of the
added connectors on its page, with that `owner` and no id, and counts
the connections of the allowed owners' connectors in one statement, so
a page of fifty rows of three owners asks three questions, not fifty.
An edit's answer carries the count, since its caller was just allowed
to change it. A deny shows no count, and so does an authorizer that
gives no decision: the read or the list it rides on still answers, and
the outage is logged. The owner policy allows `connector.update` with
no id that names the caller as `owner`, so a person sees the count of
their own connectors.

### What an added connector's view carries

A client draws an added connector from its view alone:

| Member | What it is |
|---|---|
| `id`, `owner` | the connector's id, and whose it is, as the authorizer named it at the add |
| `name`, `title`, `description`, `icon` | its label and presentation |
| `kind`, `url`, `hosts` | `mcp`, the server's address, and the one host a credential goes to |
| `auth.type` | `none`, `oauth` or `token` |
| `auth.scopes` | for `oauth`, what a sign-in asks for |
| `auth.inject`, `auth.hint` | for `token`, where the key goes, and "API key" when the add found the server takes one |
| `auth.client` | for `oauth`, how Pons identifies itself: `own`, the client registered at the server; `document`, the connector's client metadata document; `registered`, a registration the installation keeps |
| `auth.redirect_uri` | with `auth.client` `own`, the address to register that client with: the shared callback, or the issuer's own when the server sends no `iss` |
| `tools.read_only`, `tools.hidden` | its tool marks |
| `disabled`, `vouched` | whether its owner turned it off, and whether the authorizer vouched for it at the add |
| `connections` | to a caller who may change it, how many connections use it |

It never carries the client's id or secret.

```json
{ "name": "wiki", "id": "ctr_01jb…", "owner": "org:acme",
  "title": "Team wiki", "description": "The team's notes.", "icon": "https://wiki.example.com/icon.svg",
  "kind": "mcp", "url": "https://wiki.example.com/mcp", "hosts": ["wiki.example.com"],
  "auth": { "type": "oauth", "scopes": ["notes:read"], "client": "own",
            "redirect_uri": "https://pons.example.com/v1/callback/3f9c2a1b7d4e5f60" },
  "tools": { "read_only": ["get_*"], "hidden": [] },
  "disabled": false, "vouched": true, "connections": 15 }
```

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
| The count of a connector's connections is asked as `connector.update`: once per owner on a list's page with no id, and with the id on a read | One answer for who administers an owner's servers, which the edit already needs, and a question per owner, not per row. An authorizer that answers nothing shows no count and fails nothing | A limit on the allow of `connector.list` and `connector.read` naming the owners the caller may change: one question per route, but a second answer the authorizer keeps in step with `connector.update`. A question per row: fifty questions for one page |
| What the add found is stored with the connector, as `sign_in`: the issuer, its token endpoint, whether it sends `iss`, and how Pons identifies itself | The view, the client metadata document's redirect address and the binding of a client's secret need it with no request; a sign-in still discovers afresh | Discovering again at a read or an edit: a request to the server for a page of a list |
| The client's secret is the five sealed columns of [[005-store-and-sealing]], prefixed `client_secret_` | Every sealed value is stored so, and a rotation rewraps it with the others | One column `client_secret_sealed`, a second shape for one value |
| The add's first request is the one discovery and the key probe make: a `tools/list` of the current revision, and `initialize` for a server of an earlier one | A server answers the add as it answers a sign-in and a probe, and the current revision lists with no handshake | `initialize` alone: a second request shape for one question |
| `auth_mismatch` for `none` named for a server that asks for a credential, `oauth` for one that does not sign people in, and a client for one that does not | Each would store a connector no connect can use | A key named for a server that answered without one, or one that signs people in: a key may be optional, and many servers take a key beside a sign-in |
| `server_unreachable` beside `connector_unreachable` | At the add there is no connector yet, and the server did not answer as one that can be connected; a failure reading its authorization server after it did is `connector_unreachable`, as at a sign-in | One code for both: a client could not tell a wrong address from a broken authorization server |
| `connector.read` is asked at a connect of an added connector alone | A catalog connector is the installation's, held by the allow's `connectors`, and its connect keeps its one question | Asking it for every connect: a question per connect that every authorizer answers yes |
| An edit that names a fixed member with its stored value changes nothing | A client may send back the form it drew | Refusing every fixed member named: a client strips them first |
| A connector turned off refuses a reconnect and a replaced key as well as a connect | Each sends a request to the server, which nobody reaches through a connector turned off | Refusing a connect alone |
| A connection's tools carry `hidden` beside the effect | An administrator choosing marks sees which the marks already hide | The effect alone |

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
| A caller the authorizer lets change an added connector sees how many connections of every owner use it, on a read, in a list and in an edit's answer, with one question per owner on a list's page; nobody else does, and an authorizer that gives no decision hides it and fails nothing | `TestWhoMayChangeAConnectorSeesItsConnections` |
| An added connector's view carries its owner, url, presentation, tool marks, `auth.type`, how Pons identifies itself, `disabled`, `vouched` and, for its own client, the redirect address to register; never the client's id or secret | `TestAnAddedConnectorsView` |
| An authorizer that does not know `connector.update` answers an edit with no decision, so it fails closed | `access.TestAnAuthorizerOfAnEarlierVocabularyFailsClosed` |

## Implementation status

Built, and every criterion above has its test. The tests reach an added
connector at port 443 through `stubs.Front`, a proxy that ends a tunnel
to port 443 at the stub its TLS handshake names. Waiting: a check
against a real MCP server and its authorization server, of each way
Pons identifies itself.

## Outcome

Built on 2026-10-15.

- **Owners and lists.** An add stores the owner its allow names, and the
  list reads the added connectors of every owner the filter names.
  `PONS_MAX_ADDED_CONNECTORS`, 50 by default, is counted under a
  transaction-level lock on the owner with the insert, as a connection's
  cap is, and one more is `409 connector_limit`.
- **A connect to another owner's connector** asks `connector.read`
  first, and `connection.create` carries `connector_owner`. A catalog
  connector's connect still asks one question.
- **Edits.** `PATCH /connectors/{id}` asks `connector.update` and holds
  the table above. A member named with its stored value is no change.
  `disabled` refuses a connect, a reconnect and a replaced key with
  `409 connector_disabled`, and a call and a list of tools with `409
  connection_not_connected`, reason `connector_disabled`.
- **Vouched for.** `vouched` is read from the allow of
  `connector.create` alone, stored and shown. A vouched-for add takes
  `auth.client` with its `id` and `secret`; the secret is sealed in the
  five columns `client_secret_key_id` to `client_secret_nonce`, the
  convention of [[005-store-and-sealing]], not one column
  `client_secret_sealed`, bound to the connector's id and the token
  endpoint the add found, and rewrapped by a rotation as every sealed
  value is. A sign-in whose authorization server moved its token
  endpoint is `422 sign_in_unsupported`, `token_endpoint_changed`, and
  the secret goes nowhere else.
- **The add asks the server.** The first request is discovery's own,
  `tools/list` of the current revision and `initialize` of an earlier
  one, not `initialize` alone. What the add finds of a server that signs
  people in is stored with the connector as `sign_in`: the issuer, the
  token endpoint, whether it sends `iss`, and the client. The cap is
  counted at the insert, after the server was asked.
- **Sign-in.** An added server identifies Pons by its own client, its
  document or a registration, kept per issuer and redirect address. One
  whose authorization server does not say it sends `iss` signs in at
  `/callback/{key}`; the callback compares the key with the flow's
  issuer and the flow's recorded redirect address before the code goes
  anywhere, so an answer at the shared callback or another issuer's is
  refused.
- **The count and the view** were added to this spec on 2026-10-15,
  after the screens that show them were approved; the Decisions table
  records how the count is asked.
- **Tools.** `GET /connections/{id}/tools` follows the server's pages,
  up to ten, speaks an earlier revision's session and ends it, refreshes
  a refused token once, and carries `hidden` beside the effect.

The authorizer rolls before Pons. An authorizer built on
`latere.ai/x/pkg/authz/server` that does not know `connector.update`
answers it `400`, which Pons reads as no decision: an edit is `503
authorizer_unavailable`, and a read or a list shows no count. One that
does not read `connector_owner` answers a connect as before, and a
connect to another owner's connector stays closed until it allows
`connector.read` of it. An allow of `connector.create` that carries
`vouched` sent to a Pons that predates it is a key that Pons does not
know, and every add fails closed with `503` until Pons rolls.
