# Changelog

What changed for whoever runs `ponsd`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

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
