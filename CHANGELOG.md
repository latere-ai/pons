# Changelog

What changed for whoever runs `ponsd`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

### Fixed

- **The release is published.** v0.5.0 stopped before it published anything,
  so it has no image tag and no GitHub release. This release carries what
  v0.5.0 lists.

## v0.5.0 - 2026-11-01

### Changed

- **Releases are built, signed and published by the shared release stages
  in latere-ai/ci.** The image signature and the signed `checksums.txt` now
  name those stages, run for this repository; SECURITY.md gives the
  commands that check a release, and the release workflow runs them
  against every release it publishes.

## v0.4.3 - 2026-10-21

### Fixed

- **Built with Go 1.27.3,** which fixes GO-2026-6809, a flaw in the
  standard library's certificate verification that this code can reach.

## v0.4.2 - 2026-10-20

### Added

- With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the server also exports the Go
  runtime's metrics: memory, goroutines, GOGC, GOMAXPROCS and scheduling
  latency, as `go.memory.*`, `go.goroutine.count`, `go.config.gogc`,
  `go.processor.limit` and `go.schedule.duration`, through
  `latere.ai/x/pkg` v0.106.0.

## v0.4.1 - 2026-10-17

### Fixed

- A connector's answer cut by a time bound is a timeout, and one its caller
  left is a cancel, however the cancelled read ends. A transport may report
  a cancelled read as the end of the body: a body read past its request's
  bound then came back whole and short, and a streamed answer ended by
  `PONS_STREAM_IDLE_TIMEOUT`, or left by its caller, was recorded as `ok`
  where it is now `timeout` or `canceled`.

## v0.4.0 - 2026-10-17

- Added: the rename question names the new name. `connection.update`,
  asked by `PATCH /connections/{id}`, carries `new_name`, the name the
  rename gives the connection, beside `name`, the one it has. An
  authorizer that keeps connection names to a rule of its own can now
  refuse a rename to a name outside it, as it refuses such a connect. An
  authorizer that does not read `new_name` decides a rename as it did.

- Added: a rename refused for its name says why. When your authorizer
  denies a rename with `name_unusable`, Pons answers `403 forbidden` with
  that reason in `details.reason` and `name` in `details.field`, and the
  connection keeps its name. Send this reason only to a caller you would
  let rename the connection otherwise. Every other deny of a rename is
  still `404 connection_not_found`, as is this reason on any other
  question.

## v0.3.0 - 2026-10-15

- Added: a list of connectors takes `owner`, as a list of connections
  does, and sends it in its `connector.list` question, so your
  authorizer can let a service list one person's servers, for instance
  to remove a closed account's, with a filter naming that person alone.
  A list that names no owner asks as before.

- Added: one reason of a deny of `connection.use` reaches the caller.
  When your authorizer denies a use with `kept_apart_from_google`, for
  a session that already used a connection you keep apart from this one,
  Pons answers `409 connection_not_connected` with that reason in
  `details.reason`, at the MCP and the forwarding address, so the
  session can tell the person to start a new conversation. Every other
  deny of a use is still `404 connection_not_found`. Send this reason
  only for a connection the session holds.

- Added: MCP servers added by their address for others. The owner of an
  added connector is the one your authorizer's allow of
  `connector.create` names, a string Pons gives no meaning: use one for
  a person, one for an organization and one for the whole installation.
  A list of connectors shows the added connectors of every owner the
  allow's filter names, and a connect to another owner's connector asks
  `connector.read` of it first, so an organization's members connect
  the servers its administrators added when you let them read those
  connectors. Under the owner policy an added connector stays its
  owner's alone.

- Added: for your authorizer, the action `connector.update`, asked by an
  edit with the connector's `id` and `owner`, and by a list once for each
  owner on its page with that `owner` and no `id`, to show how many
  connections use each of that owner's connectors. `connection.create`
  of a connect to an added connector sends `connector_owner`. The allow
  of `connector.create` may carry the limit `vouched: true`, which says
  someone you trust looked at the server; send it for an administrator's
  add alone. Roll your authorizer before this Pons: one built on
  `latere.ai/x/pkg/authz/server` that does not know `connector.update`
  answers it `400`, and an edit fails closed with `503
  authorizer_unavailable`. Do not send `vouched` to a Pons before this
  one: it does not know the key, and every add fails closed with `503`.

- Added: `PATCH /connectors/{id}` changes an added connector in place,
  holding from the next request on every replica with no restart: its
  `title`, `description`, `icon`, tool marks, `auth.scopes`, a
  vouched-for connector's `auth.client.secret`, and `disabled`. Its
  `name`, `kind`, `url`, `auth.type` and client id are
  `400 immutable_field`. A connector turned off stays listed; a connect
  to it is `409 connector_disabled`, a call through a connection to it
  is `409 connection_not_connected` with `details.reason`
  `connector_disabled`, and its connections and their credentials are
  kept until it is turned on. A removal is still `409 connector_in_use`
  while a connection uses it.

- Added: an add needs only the address. `auth` is optional on
  `POST /connectors`: Pons asks the server with no credential, after
  the authorizer's question and within `PONS_CREATES_PER_MINUTE`, and
  stores `none`, `oauth` or `token` from its answer, with the hint "API
  key" for a server that takes a key. An `auth` the answer does not
  admit is `422 auth_mismatch`, and a server that does not answer as one
  that can be connected is `422 server_unreachable`, with the status or
  the failure and never the address. Every add now makes these
  requests, so an address whose server does not answer can no longer be
  added.

- Added: a server added by its address signs people in. Pons identifies
  itself by a vouched-for connector's own client, `auth.client` with its
  `id` and `secret`, sealed and never answered; else by the connector's
  client metadata document; else by registering at the server, which the
  installation keeps per issuer and reuses for a second connector there.
  A server whose authorization server does not say it sends `iss` signs
  in at `/v1/callback/{key}`, its issuer's own redirect address, which
  refuses an answer meant for another server. An added connector's view
  says `auth.client` (`own`, `document` or `registered`), `disabled`,
  `vouched`, and, for its own client, `auth.redirect_uri`, the address to
  register that client with.

- Added: `GET /connections/{id}/tools`, the tools a connection's server
  lists through it, with the effect the connector's marks give each and
  whether they hide it, asked each time and recorded as no call. And
  `connections` on an added connector's view, to a caller your
  authorizer lets change it: how many connections of every owner use
  it.

- Added: `PONS_MAX_ADDED_CONNECTORS`, 50 by default: how many connectors
  one owner may add. One more is `409 connector_limit`, and other
  owners' adds go on.

- Changed: the store's schema moves to version 2, which adds columns to
  `connectors`. It runs at start as every migration does; a binary
  before this one refuses a schema at version 2.

## v0.2.0 - 2026-10-14

- Added: the MCP address. A connection of kind `mcp` is used at its
  `address`, `/v1/connections/{id}/mcp`, as a Model Context Protocol
  server over streamable HTTP: a client sends one JSON-RPC message per
  `POST` with its own token, and Pons forwards it to the connector's
  `url` with the connection's credential added, streaming the answer
  back event by event. `GET` and `DELETE` reach a server of a revision
  from 2025-03-26 to 2025-11-25, whose `Mcp-Session-Id` passes both
  ways, so any replica serves a session. Pons reads only the message's
  `method` and, for `tools/call`, `params.name`; a body that is not one
  JSON object, a duplicate or differently cased `method`, `params` or
  `params.name`, or an `Mcp-Method` or `Mcp-Name` header that differs
  from the body is `400 invalid_request`. `WWW-Authenticate`,
  `Set-Cookie` and `Location` never pass back, and a redirect is
  `502 connector_unavailable` with the reason `redirect_refused`.

- Added: for your authorizer, `connection.use` at the MCP address sends
  `connection_kind` `mcp`, `method` the protocol method (`GET` or
  `DELETE` for an earlier revision's request, none for a reply), and for
  `tools/call` the `tool` and its `effect`, `read` when a
  `tools.read_only` glob of the entry matches it. `read_only` and
  `tools` hold `tools/call` alone, so a list of tools passes, and a call
  of a tool the entry marks `hidden` is refused with `403 forbidden` on
  `tool`. An authorizer that allows `connection.use` today without
  looking at the kind allows these calls too, every tool included, so
  answer them with the limits you want before rolling this Pons.

- Changed: a key for a connector of kind `mcp` is tried before it is
  kept, by listing the server's tools, and for a server of an earlier
  revision by its handshake, a list in its session and the end of that
  session; a key the server refuses is `422 credential_refused`, and a
  server that does not answer the list with a `2xx` is
  `422 connector_unreachable`. Before, such a key was stored untried.

- Changed: the first request of discovery for a connector of kind `mcp`
  that signs people in is the current revision's `tools/list` with no
  credential, as the protocol has a client make it, in place of a `GET`.

- Changed: `PONS_MAX_REQUEST_BYTES`, 4 MiB by default, bounds the
  message a caller sends to an MCP address; a larger one is
  `413 request_too_large`, whether the connection exists or not.

- Changed: a disconnect, and the sweep of a sign-in that ran out, revoke
  a credential at its service only when no other connection holds the
  same grant: the same issuer, client id and `account`, of any owner, a
  sign-in waiting for its confirm and a reconnecting connection's own
  credential included. A service may end every token of a grant at one
  revocation, as Google does, so before, disconnecting one of a person's
  connections of one account could end the others. A skipped
  revocation is logged with `reason` `grant_held` and the `count` of
  holders, and never the account. A connection whose account was not
  read is revoked at its own disconnect, as before; give `account` to an
  entry whose service ends whole grants.

- Changed: the Google entries, Gmail, Google Calendar and Google Drive,
  give `revoke_url: https://oauth2.googleapis.com/revoke`. Add it to
  yours: the disconnect of a
  person's last connection of a Google account then removes the
  installation's access in that Google Account, while their other
  connections of it keep working until then. Keep the three on one
  client: Google ends the grant of the whole project, and Pons compares
  the client.

- Changed: protected resource metadata that names an authorization
  server at an address that is not `https`, or whose host is an IP
  address, is `422 connector_unreachable` with `details.reason`
  `scheme_not_https` or `host_not_a_name`, as an issuer or an endpoint
  of the metadata already was. Before, it was `422 sign_in_unsupported`
  with the reason `authorization_servers`.

## v0.1.2 - 2026-10-13

- Added: the limit `requests`, with which an authorizer holds a caller
  to some of a service's API: each entry is a method and a path pattern,
  such as `GET /**` or `POST /repos/*/*/issues`, where `*` is one path
  segment and a last `**` the rest of the path. A request to a forwarding
  address that no entry names is answered `403 forbidden` with the reason
  `requests`, so the caller learns the request is not allowed. Before, an
  authorizer could only deny such a request, which a caller reads as a
  connection that is not there. In the public package `authorizer`,
  `Limits` has `Requests` and `AdmitsRequest`. An older Pons refuses an
  allow that names `requests` as limits it cannot read, so roll Pons
  before an authorizer that sends it.

- Fixed: the forwarding address carries only the methods an API is
  called with, `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH` and
  `DELETE`. Any other method, `TRACE` and `CONNECT` among them, is
  refused with `400 invalid_request` before the connection is loaded,
  as the API documentation already stated.

- Added: a catalog entry's `authorize_url` may carry a query, for
  members a service needs on the authorization request, such as Google's
  `access_type=offline`, which the sign-in sends beside its own. A query
  that names one of the sign-in's own members, `response_type`,
  `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`,
  `state`, `resource` or `scope`, is refused when the catalog loads; such
  a member was replaced by the sign-in's before. The public package
  `catalog` names them as `AuthorizationMembers`. Spec 015 gives catalog
  entries for Gmail, Google Calendar and Google Drive.

- Changed: the question to the authorizer names a connection's kind,
  `mcp` or `http`, as `connection_kind`, and a connector's as
  `connector_kind`. Both were sent as `kind`, a name the shared envelope
  keeps for the resource itself and drops from the fields, so no
  authorizer ever received them. In the public package `authorizer`,
  `FieldKind` is replaced by `FieldConnectionKind` and
  `FieldConnectorKind`, and `FieldID` is removed and `id` leaves
  `Fields`, since the id is the envelope's `resource.id`: `SendsID`
  reports whether an action sends one. Code that named either constant
  needs the new names. An authorizer that read the kind of the resource's fields
  read nothing before, and reads the new names now.

- Changed: a push that names a ref outside the refs its caller may update
  is refused the way a git host refuses one, so git prints the reason.
  It was answered `403` with a JSON body, of which git printed only
  `RPC failed; HTTP 403`. Now git prints, for example, ` ! [remote
  rejected] HEAD -> main (only branches under refs/heads/agents/ may be
  pushed by this caller)` and exits non-zero. The answer is `200` with a
  report in which every ref of the push is refused, the pack is read to
  its end first so git reads the answer of a large push too, and nothing
  of the push reaches the connector. The call record stays `denied`.

- Fixed: a push larger than git's post buffer, 1 MiB by default, lands
  through a git address. git sends such a push after a probe, a request
  that names no ref, and Pons answered the probe `400 invalid_request`,
  so git stopped with `RPC failed; HTTP 400`.

## v0.1.1 - 2026-10-13

- Fixed: the release pipeline attests the image's bill of materials and
  provenance only while the repository is public, since GitHub keeps
  attestations for a private repository only on a higher plan. v0.1.0
  published nothing for that reason.

## v0.1.0 - 2026-10-13

- Added: the release pipeline. A `v*` tag on a commit whose verify run
  passed builds `ponsd` for linux/amd64 and linux/arm64, signs it,
  attests its bill of materials and provenance, tags the image at
  `ghcr.io/<owner>/ponsd:<tag>`, and creates the GitHub release from
  this file.
- Added: the server, `ponsd`, with three commands: `serve`, `check` and
  `version`. It is configured by its environment, every variable named
  `PONS_*`.
- Added: the catalog, one YAML file an operator writes, validated whole at
  start, with a secret named by a reference to a variable or a file and
  never written in it. `catalog/example.yaml` shows one connector per way
  to give access.
- Added: the API of the catalog and of connections: list, read, add and
  remove a connector; connect one with a key, a client of your own or no
  credential; list, read, rename and disconnect a connection; replace its
  key; read its call records. `GET /v1/openapi.yaml` is the contract.
- Added: every credential is sealed at rest under a data key of its own,
  wrapped by the first key of `PONS_SEALING_KEYS`; prepending a key and
  restarting rewraps every value, and `ponsd check` reports what remains.
- Added: callers are verified against the issuers of `PONS_OIDC_ISSUERS`,
  and every request is asked of the authorizer at `PONS_AUTHORIZER_URL`,
  or decided by the owner policy when none is set.
- Added: `GET /v1/connections?owner=` asks the authorizer
  `connection.list` with that `owner` in the resource, so an authorizer
  lets a service list one person's connections by naming that person in
  its filter. A list that names no owner asks as before.
- Added: Postgres through `PONS_DATABASE_URL`, served through
  `PONS_DATABASE_POOL_URL` when a pooler is in front; with neither the
  server runs on a store in memory and says so.
- Added: a connector of kind `http` takes `git` and `http` in the
  catalog: a git host beside its API, where the credential goes on a git
  request, the requests that only read, and the headers that pass each
  way.
- Added: a connection of kind `http` is reached at two addresses: its
  `address`, which forwards plain HTTP to the connector's API, and its
  `git_address`, which carries git's clone, fetch and push to the
  connector's git host. The credential is added on the way out and the
  caller's own token removed; a path cannot leave its connector, a
  redirect elsewhere is not followed, and a push is held to the refs the
  authorizer's allow names. Each request leaves a call record.
- Added: a key pasted for a connector of kind `http` is tried against
  the connector before it is kept, and a client of `client_credentials`
  is minted for once; a refused one answers `422 credential_refused` and
  nothing is stored.
- Added: connecting a catalog connector by signing in to the other
  service. The connect answers the connection, `pending`, with the
  address to send the person's browser to; the browser comes back to
  `PONS_RETURN_URLS` with a code, and `POST
  /v1/connections/{id}/confirm` makes the connection usable. An
  authorization server is found from the catalog's endpoints, its
  issuer, or the connector's protected resource metadata, and Pons names
  itself by the catalog's client, a client metadata document at
  `/v1/client`, or by registering. `POST /v1/connections/{id}/reconnect`
  signs in again, and a disconnect revokes where the service offers it.
  A connector a person adds cannot sign people in yet.
- Added: a credential is refreshed before it ends by one writer across
  replicas, a refresh token rotated in the same write, and a refused
  credential moves its connection to `needs_reconnect`.
- Added: a connector in GitHub's shape: signed in through a GitHub App,
  its account read once, a link to choose repositories, and git and the
  REST API carried through its two addresses.
