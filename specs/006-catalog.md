---
title: "Catalog: the file an operator writes, the members of each way to give access, a connector a person adds, tool marks"
status: drafted
track: core
depends_on:
  - specs/002-objects.md
affects: [catalog/, internal/config/, internal/httpapi/, internal/store/]
effort: medium
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Catalog

## Overview

The catalog is the set of connectors an installation offers, written
by its operator as one YAML file and read at start. A person may also
add a connector of their own by its address, which is theirs alone.
This spec fixes the file and its validation, the members of each way
to give access, how a secret is named without being written, the hosts
a credential may be sent to, the marks that say which tools only read,
and what a person may add.

## Current state

Nothing is built. A sandbox control plane in a sibling project is the
precedent: it declares each secret with the hosts it may be sent to
and the place it is put, a header and a format, and refuses a scope
aimed at an address or a private name. A connector's `hosts` and
`inject` follow it, and the host patterns are those of the shared
package `latere.ai/x/pkg/hostmatch`, used unchanged so an operator
learns one rule.

## Design

### The file

`PONS_CATALOG_FILE` names one YAML file with one top-level key,
`connectors`, a list of entries. With the variable unset the catalog is
empty and the server says so at start. The members are the connector's
fields of [[002-objects]]:

| Member | Required | Rule |
|---|---|---|
| `name` | yes | a DNS label of at most 40 characters, unique in the file |
| `title` | yes | at most 60 characters |
| `description` | no | at most 200 characters |
| `icon` | no | an https URL |
| `kind` | yes | `mcp` or `http`. Kind `http` may also give `git` and `http`, whose members are [[014-http-forwarding]]'s |
| `url` | yes | an https URL with a host, no user part and no fragment |
| `hosts` | no | host patterns, below. The host of `url` when absent |
| `auth` | yes | `type` and the members of that type, below |
| `tools` | no | `read_only` and `hidden`, two lists of globs, below |

`catalog.Load` reads the file once and validates all of it before the
server serves. Any of these refuses the start, with one line per
problem naming the entry and the member: a key the format does not
describe, at any level, including a member of another `auth.type`; a
`name` that is not a DNS label or is used twice; a `url`, an `icon` or
an endpoint under `auth` that is not https; a secret written as a
value; a reference that does not resolve; a host pattern that fails
the rule below, or `hosts` that do not cover the host of `url`; an
empty glob.

```text
catalog: connectors[0] "tracker": auth.client.secret: write a reference, {env: NAME} or {file: /path}, not a value
```

Changing the catalog is a restart. Nothing reloads the file, so every
replica of one rollout serves the same connectors. `ponsd check` runs
the same validation and serves nothing.

### Ways to give access

**`oauth`**: a person signs in at the service ([[007-sign-in]]).

| Member | Default | Meaning |
|---|---|---|
| `discovery` | `resource` for kind `mcp`, required for `http` | how the authorization server is found. `resource`: the server publishes its protected resource metadata. `issuer`: the entry names an authorization server with standard metadata. `none`: the entry gives the endpoints |
| `issuer` | | an https URL. Required with `issuer`. With `resource`, required when `client` is given, naming the server that client is registered with. With `none`, optional: what an `iss` in an answer is compared with. An answer without `iss` is accepted only from a server the entry names, by `issuer` or by its endpoints ([[007-sign-in]]) |
| `authorize_url`, `token_url` | | required with `discovery: none`, refused otherwise |
| `revoke_url` | | optional with `discovery: none`, refused otherwise |
| `client.id`, `client.secret` | | a client the operator registered with the service. `secret` is a reference, absent for a public client. Required with `discovery: none` |
| `scopes` | | the scopes to ask for, in place of the ones the server names |
| `resource` | `true` for `mcp`, `false` for `http` | whether the request names the server a token is for (RFC 8707). The protocol requires it of a client, so it is turned off only for a server that refuses the member |
| `account` | | `{url, field}`: an https URL whose host matches `hosts`, read once after the sign-in for the connection's `account` ([[013-github-connector]]) |

Any entry may also give `links.manage`, an https URL a client shows to
change what the other service grants, which Pons never fetches
([[013-github-connector]]).

**`token`**: a person pastes a key.

| Member | Default | Meaning |
|---|---|---|
| `inject.header` | `Authorization` | the request header the key is placed in |
| `inject.format` | `Bearer {value}` | the header's value, with `{value}` exactly once |
| `hint` | | one sentence, at most 200 characters, telling a person where to get the key |

`inject.header` is a field name the carrier does not itself set, remove
or pass ([[008-carrying-a-call]]), and `inject.format` holds visible
ASCII and spaces only.

**`client_credentials`**: the connection holds its owner's client id
and secret, given at connect ([[003-api]]), and a token is minted at
use. The entry gives `token_url`, required, `scopes` and `audience`.

**`none`**: no credential and no members. The connection only records
that its owner turned the connector on.

### Secrets

A secret is never in the file. Where one belongs, the file holds a
reference with exactly one member: `{env: NAME}`, the value of a
variable, or `{file: /path}`, the contents of a file at an absolute
path. At start each reference is resolved once to prove it resolves,
and the value is dropped. It is read again at each use, with one
trailing newline removed, so a file can be rotated in place. The one
secret a catalog names is an `oauth` client's: those of `token` and
`client_credentials` belong to a connection and arrive through the API.
A connector read through the API shows of `auth` only `type`, `scopes`,
`inject` and `hint`: no client, no reference and no endpoint.

### Hosts

`hosts` lists the hosts a credential of this connector may be sent to.
A pattern is what `hostmatch.ValidPattern` accepts with no option,
after lowercasing and removing a trailing dot: an exact name of two
labels or more, or one leading `*.` before such a name. `*.example.com`
matches every name under `example.com` at any depth and not
`example.com` itself. A pattern holds no port: the port is the one of
`url`. The package judges syntax only, so the catalog's host rule adds:

- an IP literal, in any notation a resolver reads as one: a host whose
  last label is all digits or begins with `0x`;
- a single label, since the option that admits one is not passed;
- a name that is loopback, link-local or private by its spelling:
  `localhost`, and any name under `localhost`, `local`, `internal` or
  `home.arpa`.

The rule is one function of `catalog`, which the catalog's validation,
the route that adds a connector and the dialer all call.

`hosts` must cover the host of `url`: `hostmatch.New(hosts,
normalize).Matches` is true for it. `url: https://example.com/mcp` with
`hosts: ["*.example.com"]` is refused, since the wildcard does not
match the bare name. A name says nothing about the address it resolves
to, so the dialer of [[009-outbound-requests]] is the second check: it
refuses an address that is not public when it connects, and sends a
credential to a host of this list only. `hosts` governs a call. A
refresh token or a client secret is sent only to the token endpoint and
the revocation endpoint recorded with it ([[007-sign-in]]).

### Tool marks

`tools.read_only` and `tools.hidden` are globs over tool names. In a
glob `*` stands for any run of characters, the empty one included, and
every other character for itself. A glob matches a whole name, by case.

- **The effect of a tool call** is `read` when a `read_only` glob
  matches the tool and `write` otherwise, so an entry with no marks
  makes every tool `write`. The effect is what the authorizer is asked
  about, what a read-only allow refuses, and what a record keeps
  ([[008-carrying-a-call]]).
- **A hidden tool** is one a caller should not offer, and the carrier
  refuses a call to it.

A server's own hints about a tool are not trusted and not read. The
protocol has a client treat them as untrusted unless the server is
trusted, and a server a person added is not. The marks reach a caller
on the connection object ([[002-objects]]), where a caller that asks a
person before a change learns which tools change something.

### A connector a person adds

`POST /connectors` ([[003-api]]) stores a connector with its owner
([[005-store-and-sealing]]). Its address is supplied by a person, so
it is held to more than a catalog entry:

- `kind` is `mcp`. A connector of kind `http` comes from the catalog
  alone, since its paths and headers are the operator's to judge.
- `auth.type` is `oauth`, `token` or `none`. For `oauth`, discovery is
  `resource`, the request names the server, there is no registered
  client, and `auth` takes `scopes` alone. Pons identifies itself by
  the connector's own client metadata document alone, and the
  authorization server's metadata must set
  `authorization_response_iss_parameter_supported` to `true`, since no
  operator vetted that server ([[007-sign-in]]); otherwise the add is
  `422 sign_in_unsupported`. For `token`, it takes `inject` and `hint`.
- `url` is https on port 443, with no user part and no fragment, and
  its host passes the host rule. `hosts` is not taken: it is the host
  of `url`. `tools` is taken.

Anything else is `400 invalid_field` or `400 unknown_field`. Its name
is unique among its owner's connectors, and a reference to it is its
id, so it may spell a catalog name without shadowing it. To anyone but
its owner it is `404 connector_not_found`, in a list and by id.

### A connector that is gone

An entry removed from the file takes nothing with it. A connection to
it is kept with its sealed credential and reads with empty marks, and a
call to it answers `409 connection_not_connected` with `details.reason`
`connector_removed`. Restoring the entry makes it usable again. An
entry whose `kind` or `auth.type` no longer equals a connection's copy
is, for that connection, gone. A name is never reused for another
service, since a connection to the old one would send its credential to
the new one's hosts. The file cannot detect that; the operator keeps
the rule.

### The example file

`catalog/example.yaml` ships with the repository, one connector per way
to give access, for invented services:

```yaml
connectors:
  - name: tracker
    title: Example Tracker
    description: Read and file the issues of your projects.
    kind: mcp
    url: https://mcp.tracker.example.com/mcp
    auth:
      type: oauth
      discovery: issuer
      issuer: https://login.example.com
      client: {id: pons, secret: {env: TRACKER_CLIENT_SECRET}}
      scopes: ["issues:read", "issues:write"]
    tools:
      read_only: ["search_*", "get_*", "list_*"]
      hidden: ["delete_project"]
  - name: search
    title: Example Search
    kind: mcp
    url: https://api.search.example.net/mcp
    auth:
      type: token
      inject: {header: X-Api-Key, format: "{value}"}
      hint: Create a key under Settings, API keys, at search.example.net.
    tools: {read_only: ["*"]}
  - name: warehouse
    title: Example Warehouse
    kind: mcp
    url: https://mcp.warehouse.example.org/mcp
    hosts: ["mcp.warehouse.example.org"]
    auth:
      type: client_credentials
      token_url: https://login.warehouse.example.org/oauth/token
      scopes: ["query"]
      audience: https://mcp.warehouse.example.org
  - name: weather
    title: Example Weather
    kind: mcp
    url: https://weather.example.org/mcp
    auth: {type: none}
    tools: {read_only: ["*"]}
```

### The package

`catalog` is public and imports nothing that dials. It holds the types,
`Load`, `Validate` for one connector with a flag for one a person adds,
`CheckHost`, and the carrier's `Marks.Effect(tool)` and
`Marks.Hidden(tool)`.

## Not in this spec

How discovery, the client and the scopes are used ([[007-sign-in]]);
how the credential is placed and a hidden tool refused
([[008-carrying-a-call]]); what the dialer refuses
([[009-outbound-requests]]); the table of added connectors
([[005-store-and-sealing]]); a code host's own `auth.type`
([[013-github-connector]]).

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| A file with an unknown key at any level, a duplicate name, a non-https `url`, an inline secret, an unresolved reference or a bad host pattern refuses the start, and each message names the entry and the member | `catalog.TestLoadRefusals`, one bad file per rule |
| The example file loads with one entry per `auth.type`, and each type takes its own members with their defaults and refuses another type's | `catalog.TestExampleFileLoads`, `catalog.TestAuthMembers` |
| A reference is read at each use: a file rewritten between two uses gives the new value without a restart | `catalog.TestSecretRefIsReadAtUse` |
| A connector read through the API carries no client, no reference and no endpoint | `httpapi.TestConnectorShowsNoSecretReference` |
| An IP literal in each notation, a single label, `localhost` and a name under `local`, `internal` or `home.arpa` are refused; `*.example.com` does not cover `example.com`; absent `hosts` are the host of `url` | `catalog.TestHostRule`, `catalog.TestHostsCoverTheURL` |
| The effect is `read` only for a tool a `read_only` glob matches; a glob matches a whole name by case | `catalog.TestEffect`, `catalog.FuzzGlob` |
| An added connector of kind `http`, on another port, with `hosts`, with a client or of type `client_credentials` is refused; one of type `oauth` whose server takes no client metadata document or does not say it sends `iss` is `422 sign_in_unsupported`; and it is `404` to anyone but its owner | `httpapi.TestAddedConnectorRules`, `TestAnAddedConnectorIsItsOwnersAlone` |
| A connection whose connector left the catalog is kept, answers `409` with `connector_removed`, and works again when the entry returns | `TestRemovedConnectorKeepsItsConnections` |
| `catalog` imports no package that dials | `TestPublicPackagesDialNothing` |
