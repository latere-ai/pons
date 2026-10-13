# The API

For whoever builds the app in which a person connects services, and the
caller that then uses those connections. The full reference is the
OpenAPI 3.1 document [`api/openapi.yaml`](../api/openapi.yaml), which
every installation also serves at `GET /v1/openapi.yaml` with no token.
This page is the orientation around it: how to authenticate, how a
person connects a service, how a caller uses a connection, and the
errors to branch on.

Every route is under `PONS_PUBLIC_URL` and the base path,
`PONS_BASE_PATH`, which is `/v1` unless the installation changes it. The
examples use `http://localhost:8080/v1`.

## Authentication

Every request carries `Authorization: Bearer <token>`: a token from an
issuer the installation lists in `PONS_OIDC_ISSUERS`, naming an audience
of `PONS_OIDC_AUDIENCE` (`pons` by default), not expired, and, when it
carries `iat`, minted less than 24 hours ago. Pons has no login and no API key of its own.
Four routes take no token: the sign-in's callback, the two client
metadata documents, and the OpenAPI document. The probes, `/livez`,
`/readyz` and `/version`, sit at the root, outside the base path.

The caller is the token's issuer and `sub` joined by a pipe,
`https://login.example.com|alice`. That string is the `owner` of what
the caller creates, and what the installation's authorizer is asked
about. Every request is asked about before anything acts. A refusal to
create or to list is `403 forbidden`. A refusal about an object that
exists answers exactly as a missing one, `404`, so an id cannot be
probed for what somebody else owns.

## Requests and answers

**Bodies** are JSON, at most 64 KiB. A member the API does not describe
is `400 unknown_field`, with the member in `details.field`.

**Lists** answer `{"items": [...], "next_cursor": "..."}`, newest first,
except the catalog part of `GET /connectors`, which keeps the file's
order.
Pass `next_cursor` back as `cursor` for the next page; its absence is
the end. `limit` is 50 by default and at most 200.

**Creating twice.** `POST /connectors` and `POST /connections` take an
`Idempotency-Key` header. The same key from the same caller within 24
hours creates nothing and answers what the first request made, as it is
now. The repeat is still rate limited and authorized, and a key or a
client is tried against the service again. For a connection made by
signing in that still waits for its sign-in, the repeat answers it with
a new `authorization_url`, which replaces the first.

**Identifiers.** A connection's id starts with `con_`, and a connector a
person added has an id that starts with `ctr_`. A catalog connector is
named by its `name`.

## Connectors

| Route | What it does | Asks |
|---|---|---|
| `GET /connectors` | the catalog in the order of its file, then the connectors the caller may see that people added; `kind`, `limit`, `cursor` | `connector.list` |
| `GET /connectors/{ref}` | one connector, by catalog name or id | `connector.read` |
| `POST /connectors` | add a connector by its address | `connector.create` |
| `DELETE /connectors/{id}` | remove a connector the caller added; `409 connector_in_use` while a connection uses it | `connector.delete` |

A connector reads as its `name`, `title`, `description`, `icon`, `kind`,
`url`, `hosts`, its tool marks, and of `auth` only `type`, `scopes`,
`inject` and `hint`, with `inject` for a pasted key alone. One a person
added also carries its `id` and `owner`. Its `git`, `http` and `links`
are not shown.

A person may add a connector of their own by its address, which is
theirs alone and `404` to everyone else. It is of kind `mcp`, its `url`
is `https` on port 443 and a public name, and its credential goes to
that host alone. It takes `auth.type` `token` or `none`; one whose
people sign in, `oauth`, is refused with `422 sign_in_unsupported` in
this release. Since this release does not serve the address of kind
`mcp`, an added connector can be connected and not yet called.

## Connecting

`POST /connections` connects a connector for its owner.

| Member | Rule |
|---|---|
| `connector` | a catalog name, or the id of a connector the owner added. Required |
| `name` | the connection's name, unique among the owner's; the connector's name by default. `409 name_taken` when the owner holds one |
| `owner` | the owner to connect for, when it is not the caller, such as a service connecting for a person. The authorizer decides whether the caller may |
| `credential.value` | the key, for a connector of `auth.type` `token`. At least 8 bytes. Write-only |
| `credential.client_id`, `credential.client_secret` | the owner's own client, for `client_credentials`. Write-only |
| `return_to` | for `oauth`: where the person's browser goes after the sign-in. It must be an entry of `PONS_RETURN_URLS`, or lie under one that ends in `/` |
| `scopes` | for `oauth`: scopes to ask for beside the connector's own |

A credential is accepted once and never returned: no route, list, error
or log line carries it.

### With a key, a client, or nothing

A connector of `auth.type` `token`, `client_credentials` or `none` is
connected at once, and the answer is `201` with the connection,
`connected`:

```sh
curl -s http://localhost:8080/v1/connections \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"connector": "forge", "credential": {"value": "your-forge-key"}}'
```

A key for a connector of kind `http` is tried first with one `GET` of
the service's `url`, and a client is tried by minting a token once. A
key the service refuses with `401` or `403`, or a client its token
endpoint answers `invalid_client`, is `422 credential_refused`. Any
other failure to reach or use the service is
`422 connector_unreachable`. In both cases nothing is stored.

### By signing in

A connector of `auth.type` `oauth` signs the person in at the service.
The connect answers `201` with the connection, `pending`, and the
address to send the person's browser to:

```sh
curl -s http://localhost:8080/v1/connections \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"connector": "github", "return_to": "https://app.example.com/connected"}'
```

```json
{
  "connection": {"id": "con_01m4ts1r5ce6vetfkw19e717ar", "state": "pending", "...": "..."},
  "authorization_url": "https://github.com/login/oauth/authorize?client_id=...&code_challenge=...&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fpons.example.com%2Fv1%2Fcallback&response_type=code&state=..."
}
```

1. Keep the connection's id in the person's own session, and send their
   browser to `authorization_url`. The sign-in waits 10 minutes for them.
2. The service sends the browser to Pons's callback, which exchanges what
   it brought and sends the browser on to `return_to` with two query
   members: `connection`, the connection's id, and either `code`, a
   one-time code good for 2 minutes, or `error`, one of `access_denied`
   (the person declined), `sign_in_failed` and `flow_expired`.
3. Check that `connection` is the one this person's session started,
   and confirm with the code:

```sh
curl -s http://localhost:8080/v1/connections/con_01m4ts1r5ce6vetfkw19e717ar/confirm \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "the code the browser brought back"}'
```

The answer is the connection, `connected`. A wrong code is
`400 invalid_code` and spends the sign-in, and a sign-in whose time has
passed is `410 flow_expired`; either way, connect again. The confirm is
asked as `connection.create` for the connection's owner, so the caller
must be allowed to act for that owner. A callback that matches no live
sign-in shows the person a page saying the link has expired, and sends
nothing anywhere.

### Reconnecting

`POST /connections/{id}/reconnect` with `return_to`, and optionally
`scopes`, starts a new sign-in for a connection of `auth.type` `oauth`:
to change its account or its scopes, or after the service stopped
taking its credential. It answers `200` with the same body a connect
by signing in does, and is confirmed the same way. The connection keeps
its id and its name, and its old credential carries calls until the
confirm. The scopes asked are the ones granted before and the ones
named. A sign-in that finds another authorization server than the
connection's is `422 sign_in_unsupported` with the reason
`issuer_changed`, and nothing changes.

### Replacing a key

`PUT /connections/{id}/credential` with `{"credential": {...}}` gives a
`token` connection a new key, or a `client_credentials` connection a new
client. It is tried as at connect, replaces the old in one write, moves
a connection that needed reconnecting back to `connected`, and answers
`204`. A connection of another `auth.type` is `409 wrong_kind`.

### Reading, renaming and disconnecting

| Route | What it does | Asks |
|---|---|---|
| `GET /connections` | the connections the caller may see; `owner`, `connector`, `state`, `limit`, `cursor` | `connection.list` |
| `GET /connections/{id}` | one connection | `connection.read` |
| `PATCH /connections/{id}` | rename, with `{"name": "..."}` | `connection.update` |
| `DELETE /connections/{id}` | disconnect: the connection and its credential go in one transaction, and the credential is revoked where it recorded a revocation endpoint, from the entry or the server's metadata. `204` | `connection.delete` |
| `GET /connections/{id}/calls` | the connection's call records | `connection.read` |

`owner` narrows a list to one owner the caller may see, and never widens
it.

### The connection

| Member | What it is |
|---|---|
| `id`, `name`, `owner`, `connector` | the connection's id, its name, whose it is, and the connector it connects |
| `kind`, `auth` | the connector's kind and way to give access, as they were at connect |
| `state` | `pending` until a sign-in is confirmed, `connected`, or `needs_reconnect` when the service stopped taking the credential |
| `reason` | why it needs reconnecting: `refresh_refused`, `revoked` or `credential_refused` |
| `account` | the account at the service this connection acts as, where the connector reads one |
| `scopes` | the scopes granted |
| `address` | where a caller reaches the connection: the forwarding address for kind `http`. For kind `mcp`, an address ending in `/mcp` that this release does not serve |
| `git_address` | for kind `http` whose connector names a git host |
| `tools` | the connector's tool marks, `read_only` and `hidden` |
| `links.manage` | where a person changes what the service grants, when the connector names it |
| `created_by`, `created_at`, `updated_at`, `last_used_at`, `expires_at` | who made it and when; when it was last used; when its credential can no longer be refreshed |

Nothing in it is ever the credential.

## The addresses

A caller uses a connection of kind `http` through two addresses, each
with its own token, never the service's:

| Address | Carries |
|---|---|
| `{address}/{path}`, the forwarding address, `/v1/connections/{id}/http/{path}` | any method but `TRACE`, to the connector's `url` joined with `{path}`, the query kept |
| `{git_address}/{path}`, the git address, `/v1/connections/{id}/git/{path}` | git's smart HTTP protocol to the connector's `git.url`: a `GET` of `.../info/refs` and a `POST` to `.../git-upload-pack` or `.../git-receive-pack`. Every other request is `404`, so the address serves no web page of the git host |

Each request is asked as `connection.use`, with its method, its effect,
`read` or `write`, and what it names: the path on the forwarding
address, or `git-upload-pack` or `git-receive-pack` on the git address,
with the branches a push updates. A caller who may not use the
connection is answered `404 connection_not_found`, as for one that does
not exist.

**What Pons changes.** It removes the caller's `Authorization` and puts
the connection's credential in the place the catalog names. Toward the
service it passes `Accept`, `Accept-Encoding`, `Content-Type`,
`If-None-Match`, `If-Modified-Since` and `Range`, and the headers the
connector lists in `http.pass`; the git address passes `Accept`,
`Accept-Encoding`, `Content-Type` and `Git-Protocol`, and
`Content-Encoding` on a fetch. Everything else is removed, cookies
included. A request without `Accept-Encoding` is sent with
`Accept-Encoding: identity` on both addresses, so the service is asked
for no compression the caller did not ask for. Back to the caller it passes the status, the
body, `Content-Type`, `Content-Length`, `Content-Encoding`,
`Cache-Control`, `ETag`, `Last-Modified`, `Retry-After`, and the headers
the connector lists in `http.pass_back`. `Set-Cookie` and
`WWW-Authenticate` never pass. A `Link` header's URLs under the
service's `url` come back under the forwarding address, so a caller
that follows the next page stays on Pons, and its other URLs are
dropped. A URL inside a body is passed as the service wrote it.

**Redirects.** A redirect to a URL under the connector's own address
passes, rewritten to the connection's address. Pons follows no redirect,
and one anywhere else is `502 connector_unavailable` with the reason
`redirect_elsewhere`.

**Paths.** The path is read as the caller escaped it, and refused with
`400 invalid_request` when it holds a `.` or `..` segment, an empty
segment, a trailing slash included, a backslash, an encoded slash or
backslash (`%2F`, `%5C`), or a control character, or when it is longer
than 2048 bytes. Nothing a request names reaches another host.

**Bodies** stream in both directions. A request body larger than
`PONS_MAX_FORWARD_BYTES`, 2 GiB by default, is ended with
`413 request_too_large`.

**Pushes.** Before any of a push leaves, Pons reads the branches and
tags it updates. Under an allow that names `refs`, a push naming any
other ref is refused, and none of it reaches the service. Pons answers
it the way a git host refuses a push, `200` with a report that refuses
every ref of the push, so git prints the rule as the reason and exits
non-zero:

```text
 ! [remote rejected] HEAD -> main (only branches under refs/heads/agents/ may be pushed by this caller)
```

The call record says `denied`. A compressed push is not git's, and is
`400 invalid_request`.

**A refused credential.** When the service answers `401`, a pasted key
moves its connection to `needs_reconnect` at once. A credential from a
sign-in is refreshed, or a client's token minted again, and a request
with no body is sent once more; a request with a body is answered the
`401` as it came, and the next request uses the new credential. A
credential the service will not renew, or refuses again once renewed,
moves the connection to `needs_reconnect` too. The request that met the
refusal and every later one answer `409 connection_not_connected` until
the person reconnects or gives a new key. A renewal that fails another
way, such as a token endpoint that does not answer, moves nothing and
answers `502 connector_unavailable`.

**From a browser.** A request carrying an `Origin` header is refused
with `403 forbidden` unless that origin is the origin of an entry of
`PONS_RETURN_URLS`.

### From a sandbox

The caller is usually code in an agent's sandbox that holds a token for
Pons and nothing of the service's. Point git at the git address, and the
agent's tools at the forwarding address:

```sh
git config --global url."$GIT_ADDRESS/".insteadOf https://forge.example.com/
git config --global http."$GIT_ADDRESS/".extraHeader "Authorization: Bearer $TOKEN"
git clone https://forge.example.com/acme/app.git

export FORGE_API="$ADDRESS"
curl -s "$FORGE_API/repos/acme/app/issues" -H "Authorization: Bearer $TOKEN"
```

`git clone` then goes through Pons, and the sandbox's token opens
nothing at the service itself. A token for Pons that carries `iat` is
accepted for at most 24 hours after it was minted, so a long-lived
sandbox is given a fresh one before then.

## Call records

A request to an address leaves a record, read with
`GET /connections/{id}/calls`, once its token is verified, its path read
and its connection found. A request refused before that leaves none: one
with a bad token, `Origin` or path, one whose `Content-Length` is over
the size limit, one past the caller's or the replica's limit of requests
in flight, one the git address does not serve, a push Pons cannot read,
and one to an id that names no connection. Nor does a
request that failed inside Pons, a `500` or a `503`. A `denied` call is
recorded at most once a minute per caller and connection on each
replica, so the records show that a caller was refused, not how often.

A record says a call happened, never what it said: no argument, result,
header or query string.

| Member | What it is |
|---|---|
| `subject`, `session` | who called, and the `session` claim of their token when it carries one |
| `at`, `duration_ms` | when, and for how long |
| `method`, `tool`, `effect` | the HTTP method; the path, or the git service; `read` or `write` |
| `refs` | how many refs a push named |
| `outcome` | `ok`, `denied`, `not_connected`, `upstream_error`, `upstream_refused`, `timeout` or `canceled` |
| `status` | the service's status, when it answered |
| `bytes_in`, `bytes_out` | the sizes of the request and the answer bodies |

Records are kept for `PONS_RECORDS_RETENTION`, 30 days by default.

## Errors

Every error Pons raises at a route it serves is one JSON body:

```json
{
  "error": {
    "code": "connection_not_connected",
    "message": "This connection needs to be connected again.",
    "details": {"reason": "credential_refused", "retryable": false, "state": "needs_reconnect"}
  }
}
```

A path or a method no route serves, such as the `address` of a
connection of kind `mcp` in this release, is answered a plain `404` or
`405` with no JSON body.

Branch on `code`. `message` is a sentence to show a person, and never
changes for a code. `details.reason` says what happened in this
instance, `details.retryable` whether the same request may succeed
later, and `details.field` which member of the request is at fault. No
error carries any part of a token or a credential. On an address, a
status the service itself answered is passed on as it came, and only
the errors below are Pons's.

| Code | Status | Means |
|---|---|---|
| `invalid_request` | 400 | the request could not be read; on an address, a path that would leave its connector |
| `unknown_field` | 400 | a member the API does not describe |
| `invalid_field` | 400 | a member has a value it cannot take |
| `missing_field` | 400 | a required member is absent |
| `invalid_code` | 400 | the confirm's code is wrong; the sign-in is spent |
| `missing_token` | 401 | no bearer |
| `invalid_token` | 401 | the bearer was refused; `details.reason` says why, such as `expired` or `audience` |
| `forbidden` | 403 | the authorizer refused a create or a list, or a limit of its allow refused the request; `details.field` names the limit's member. A push outside `refs` is answered in git's protocol instead, above |
| `connector_not_found` | 404 | no such connector, or one the caller may not see |
| `connection_not_found` | 404 | no such connection, or one the caller may not use |
| `name_taken` | 409 | the owner already holds one of that name |
| `connector_in_use` | 409 | a connection still uses the connector |
| `connection_not_connected` | 409 | the connection cannot be used now; see below |
| `wrong_kind` | 409 | the connection does not take this request: an address its kind lacks, or a credential its `auth` does not take |
| `flow_expired` | 410 | the sign-in ran out; start it again |
| `request_too_large` | 413 | the body is over its limit |
| `connector_unreachable` | 422 | the service could not be reached or used to try a credential or start a sign-in |
| `sign_in_unsupported` | 422 | the service cannot be connected by signing in; `details.reason` names the step |
| `credential_refused` | 422 | the service refused the key or the client |
| `rate_limited` | 429 | too many requests; retryable, with `Retry-After` |
| `internal` | 500 | something failed inside Pons |
| `connector_unavailable` | 502 | the service did not answer, or redirected elsewhere; retryable unless the reason is `redirect_elsewhere` |
| `authorizer_unavailable` | 503 | no decision could be had; nothing was done; retryable |
| `sealing_unavailable` | 503 | the installation has no sealing key |
| `connector_timeout` | 504 | the service did not start its answer in time; retryable |

`connection_not_connected` is the one an app that speaks for a person
acts on. `details.state` is the connection's state, and
`details.reason` is the connection's own reason when it has one,
`not_confirmed` for a sign-in not yet confirmed, `connector_removed`
when its catalog entry is gone, or `scope_insufficient` when the service
asked for more scopes, which `details.scopes` names. In each case, offer
the person to reconnect, or to give a new key.
