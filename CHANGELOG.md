# Changelog

What changed for whoever runs `ponsd`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

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
  Connecting by signing in to the other service is not offered yet and
  answers `422 sign_in_unsupported`.
- Added: every credential is sealed at rest under a data key of its own,
  wrapped by the first key of `PONS_SEALING_KEYS`; prepending a key and
  restarting rewraps every value, and `ponsd check` reports what remains.
- Added: callers are verified against the issuers of `PONS_OIDC_ISSUERS`,
  and every request is asked of the authorizer at `PONS_AUTHORIZER_URL`,
  or decided by the owner policy when none is set.
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
