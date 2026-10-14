---
title: "Distribution: the repository scaffold, the binary and its images, configuration, the stubs, test tiers, and release"
status: in-progress
track: core
depends_on:
  - specs/001-architecture.md
affects: [cmd/ponsd/, internal/config/, internal/version/, test/stubs/, deploy/, docs/, Makefile, Dockerfile, .lateregate.yaml, .githooks/, .github/, CHANGELOG.md, SECURITY.md]
effort: large
created: 2026-10-12
updated: 2026-10-14
author: changkun
---

# Distribution

## Overview

How Pons is built, configured, tested and shipped: the layout of the
repository, what the binary and its image contain, the one table of
configuration variables, the stub services tests run against, the tiers
of tests and which claims each proves, an example installation, and how
a release is cut. This spec is implemented first, so that every later
spec lands into a repository with its gate already running.

## Current state

The scaffold is built; see Implementation status.

A document service in a sibling project is the model for what follows:
its gate configuration, its two hooks, its verify and release
workflows, its changelog rule, its image and its configuration table.
Two things of it are not carried over. It has a second binary and
roles, and Pons is one binary with one role. It has a development flag
with a static token, and Pons has none: with no database it runs on the
memory store and is otherwise configured the same.

## Design

### Layout

| Path | Holds |
|---|---|
| `cmd/ponsd/` | the binary: `serve`, `check`, `version`; the e2e tier sits beside the function `serve` runs |
| `api/` | public: `openapi.yaml`, embedded for the server to serve |
| `authorizer/` | public: the action vocabulary and the limits of an allow |
| `catalog/` | public: the catalog file's types and its validation |
| `internal/access/` | verification, the authorizer client, the owner policy |
| `internal/store/` | the store interface, the Postgres and memory adapters, sealing, the migrations |
| `internal/signin/` | discovery, registration, the flow, refresh |
| `internal/carry/` | the carrier |
| `internal/dial/` | the dialer |
| `internal/httpapi/` | routes, errors, the OpenAPI document served |
| `internal/config/` | configuration, read once into one typed value |
| `internal/id/` | prefixed, time-ordered identifiers |
| `internal/version/` | the build's version, stamped by the linker |
| `test/stubs/` | a stub issuer, authorizer, connector, authorization server, API and git host |
| `deploy/base/` | manifests for a cluster, with no host or account in them |
| `deploy/examples/generic/` | an example installation: settings, a catalog, the template of the Secrets, a pooler |
| `docs/` | running it, the configuration reference, the catalog guide, the API guide |
| `.githooks/`, `.github/workflows/` | two hooks; the verify, release and gate bump workflows |

The public packages are the three a consumer or an authorizer imports:
`api`, `authorizer` and `catalog`. The module path is the one `go.mod`
declares. Go, current release, no cgo. Community files: `LICENSE`
(Apache-2.0), `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`,
`CHANGELOG.md`.

### The gate

`make check` runs `go tool lateregate`, the same bar every push and
every hook runs: formatting, no cgo, license notices, the spec tree,
the identity and Postgres declarations, lint, the vulnerability check,
and the suite under the race detector with a coverage floor of 90% per
package. The gate lives in `latere.ai/x/ci-gate`, pinned as a tool in
`go.mod`. `.lateregate.yaml` holds only what is this repository's own:

| Block | Declares |
|---|---|
| `spec` | in the repository today: the status vocabulary, the required frontmatter and sections, numbered files, wikilinks, the archive |
| `license` | `spdx: Apache-2.0` and the holder; every Go file, the `Makefile` and the `Dockerfile` carry the notice |
| `identity` | `role: core`, `audience: pons`, `config_prefix: PONS`, `reached_by: self-hosted`, and the `api_group` a core must name |
| `postgres` | `role: pooled` with `prefix: PONS`: serving reads `PONS_DATABASE_POOL_URL` and migrations read `PONS_DATABASE_URL` |
| `cover` | the module path trimmed from the report, and one entry per package that cannot clear the floor, with its reason |

The role `core` holds the repository to the shared verifier and the
shared authorizer client, to reading no claim for meaning, and to
naming no installation. The suite runs once with coverage taken over
every package, so a package's figure is what the three tiers below
reach together.

`make build` builds `out/ponsd` with the version, the commit and the
date stamped in. `make run` builds and starts the server on the memory
store with `PONS_PUBLIC_URL` set to `http://localhost:8080`, against
the issuer the developer's environment names. `make specs` checks the
spec tree alone. `make openapi` runs the tests that hold the router to
the contract. `make hooks` points git at `.githooks`, whose two hooks
only call the gate: `lateregate hook` before a commit and `lateregate
prepush` before a push.

One workflow, `verify`, runs on every push to main and every pull
request: the gate through the shared pipeline, a check that the module
files are tidy, the `deploy` job, which renders the example with
`kubectl` and fails on a skipped test, and the `image` job. Every
third-party action is pinned by commit.

### The binary

`ponsd` takes one command and no flag. It is configured by its
environment.

| Command | Does |
|---|---|
| `serve` | reads the configuration and the catalog, applies the schema, and serves until a signal |
| `check` | reads the configuration and the catalog as `serve` would, serves nothing, and prints one line per finding |
| `version` | prints the version, the commit and the date of the build |

`check` fails, with a status that is not zero, on everything `serve`
would refuse at start. It applies the schema as `serve` does, since a
database `serve` would migrate is not one to refuse. It reports three things an operator should see:
per table, how many sealed values are not wrapped under the first
sealing key, which is how far a key rotation has come, and how many no
listed key wraps, which fails the check ([[005-store-and-sealing]]);
`PONS_DIAL_ALLOW_PRIVATE`, when set; and `PONS_OUTBOUND_PROXY`, when
set ([[009-outbound-requests]]). The counts need the database and are
left out on the memory store.

On `SIGINT` or `SIGTERM` the server stops accepting connections, gives
open requests 25 seconds to finish, and then closes the streams that
are left.

### The image

There is one image, `ponsd`: the static binary on a distroless base,
with the roots it verifies certificates against, a numeric user that is
not root, no shell and no package manager. It is built for linux/amd64
and linux/arm64 from one `Dockerfile` that cross-compiles. It stays
under 40 MiB, and it starts and answers with a read-only root file
system and every capability dropped. `ponsd` starts no other program
and writes no file.

### Configuration

Every variable is `PONS_*` and is listed once, here, with the spec that
owns its meaning. `internal/config` reads each once at start into one
typed value, and no other package reads the environment. The table is
generated into `docs/configuration.md`, and a test fails when the
binary reads a variable the table lacks.

| Variable | Default | Owner |
|---|---|---|
| `PONS_ADDR` | `:8080` | this spec |
| `PONS_PUBLIC_URL` | none; required | this spec |
| `PONS_BASE_PATH` | `/v1` | [[003-api]] |
| `PONS_DATABASE_URL` | none: the memory store | [[005-store-and-sealing]] |
| `PONS_DATABASE_POOL_URL` | none: serving opens `PONS_DATABASE_URL` | [[005-store-and-sealing]] |
| `PONS_SEALING_KEYS` | none; required with a database | [[005-store-and-sealing]] |
| `PONS_OIDC_ISSUERS` | none; required | [[004-identity-and-authorization]] |
| `PONS_OIDC_AUDIENCE` | `pons` | [[004-identity-and-authorization]] |
| `PONS_AUTHORIZER_URL` | none: the owner policy | [[004-identity-and-authorization]] |
| `PONS_AUTHORIZER_TOKEN_FILE` | none; required with the authorizer's URL | [[004-identity-and-authorization]] |
| `PONS_CATALOG_FILE` | none: an empty catalog | [[006-catalog]] |
| `PONS_RETURN_URLS` | none: no sign-in can start | [[003-api]] |
| `PONS_CLIENT_NAME` | `Pons` | [[007-sign-in]] |
| `PONS_CLIENT_URI` | none: the member is left out | [[007-sign-in]] |
| `PONS_RECORDS_RETENTION` | `720h` | [[010-records-and-observability]] |
| `PONS_MAX_CONNECTIONS_PER_OWNER` | 100 | [[004-identity-and-authorization]] |
| `PONS_CREATES_PER_MINUTE` | 10 | [[004-identity-and-authorization]] |
| `PONS_MAX_INFLIGHT_PER_SUBJECT` | 32 | [[008-carrying-a-call]] |
| `PONS_MAX_INFLIGHT` | 1024 | [[008-carrying-a-call]] |
| `PONS_MAX_REQUEST_BYTES` | 4 MiB | [[008-carrying-a-call]] |
| `PONS_MAX_FORWARD_BYTES` | 2 GiB | [[014-http-forwarding]] |
| `PONS_CALL_HEADER_TIMEOUT` | `30s` | [[008-carrying-a-call]] |
| `PONS_STREAM_IDLE_TIMEOUT` | `5m` | [[008-carrying-a-call]] |
| `PONS_OUTBOUND_PROXY` | none: requests leave directly | [[009-outbound-requests]] |
| `PONS_DIAL_ALLOW_PRIVATE` | unset: public addresses only | [[009-outbound-requests]] |
| the standard OpenTelemetry variables | the SDK's own | [[010-records-and-observability]] |

`PONS_PUBLIC_URL` is the origin, and the path prefix when a proxy in
front adds one, that other services and browsers reach Pons at. Every
address Pons hands out is this URL joined with `PONS_BASE_PATH` and the
route: a connection's `address`, the redirect address it gives an
authorization server, and the addresses of its client metadata
documents.

A duration is written as Go writes one, such as `30s` and `720h`. A
size is a whole number of bytes. `PONS_OIDC_ISSUERS`,
`PONS_OIDC_AUDIENCE` and `PONS_RETURN_URLS` are comma-separated
lists; an entry of `PONS_RETURN_URLS` is an exact URL, or a prefix that
ends in `/` ([[007-sign-in]]). `PONS_AUTHORIZER_TOKEN_FILE` names a file that holds the bearer,
so a Secret is mounted and no variable carries it. The OpenTelemetry
variables are read by the telemetry setup as the SDK defines them, and
are the one exception to the prefix.

A value that does not parse is an error that names its variable and
never its value: a variable may hold a secret, and `PONS_SEALING_KEYS`
always does. A certificate authority of the operator's own is trusted
the way the process trusts any, through the system's roots.

### Refusals at start

`serve` stops before it listens, with a status that is not zero and one
line that names the variable, in each of these cases:

| Case | Why |
|---|---|
| a required variable is missing | `PONS_PUBLIC_URL` and `PONS_OIDC_ISSUERS` always; the others as the table says |
| `PONS_PUBLIC_URL` is not `https`, with a database configured | a callback and a connection's address over plain HTTP carry a code and a bearer in the clear; the memory store accepts `http` for a server on loopback |
| a database is configured and `PONS_SEALING_KEYS` is empty | a durable server that can seal nothing is a mistake to be named at start; on the memory store the server starts and answers `503 sealing_unavailable` to what would seal ([[005-store-and-sealing]]) |
| a database is configured and does not answer, its schema is newer than the binary knows, or a migration is marked dirty | [[001-architecture]], [[005-store-and-sealing]] |
| the catalog does not validate | the line names the entry and the member ([[006-catalog]]) |
| `PONS_AUTHORIZER_URL` is set and the token file is missing or cannot be read | the endpoint requires a bearer |

The first log line says which store is in use. The lines after it say
who decides, the authorizer or the owner policy, and warn when
`PONS_DIAL_ALLOW_PRIVATE` is set or a proxy is in use.

### The stubs

`test/stubs` holds six servers a test starts in its own process. Each
listens on loopback over TLS, with a certificate from one authority the
package makes at start, since the dialer speaks https only. Each
records every request it served, and each has switches a test sets on
the stub's value.

| Stub | Serves | Switches |
|---|---|---|
| issuer | a discovery document, a key set, and tokens minted for a subject, an audience and a `session` claim | an expired token, another audience, a rotated key, an issuer that does not answer |
| authorizer | the contract of [[004-identity-and-authorization]], answered from a table of subject, action and resource, with the limits of an allow | a deny, no answer, a slow answer, a malformed answer; it records every question |
| connector | a Model Context Protocol server over streamable HTTP, with a few tools, some that only read, and one streamed answer; it records the credential each request carried | a `401`, an insufficient scope `403`, a redirect, a cookie, a slow stream, a stream that never ends, an oversized body, oversized headers, and an earlier protocol revision: `initialize`, a session, `GET` and `DELETE` |
| API | a small JSON API in a code host's manner: a user, a list paged with a `Link` header, a write that records its body, a `3xx` within and one elsewhere; it records the credential each request carried | a `401`, a slow answer, a body past a limit |
| git host | git's smart HTTP over a bare repository the test seeds, through `git http-backend` under `net/http/cgi`, so a real `git` client clones and pushes; it records the credential each request carried | a `401`; the test is skipped with a stated reason when `git` is not installed, and the gate's image has it |
| authorization server | protected resource metadata on the connector, authorization server metadata, a fetch of Pons's client metadata document, dynamic registration, the proof key, refresh with rotation, revocation | one for each failure [[007-sign-in]] handles: no proof key in the metadata, no way to identify a client, a wrong or missing `iss`, metadata that names an inside address, a refused code, a refused refresh, a spent refresh token used again, a slow token endpoint, a person who declines |

`stubs.Roots` is the authority's pool, and `stubs.Resolver` maps each
stub's name under `example.com` to its listener. A test hands both to
the server with a `Permit` for the listeners, the options of
[[009-outbound-requests]], so the host rule and the address check stay
on in every test. A browser stands for the person: it follows the
sign-in's redirects by hand and returns what the last one carried. It
lives in the tests that drive a sign-in, the e2e tier's and the sign-in
package's, and not in `test/stubs`: it builds an HTTP client of its own,
which the rule that only the dialer builds one forbids to every file but
a test's. The package is public, so a consumer's own tests can start the
stubs.

### Test tiers

| Tier | Runs | Proves |
|---|---|---|
| unit | every push, in the gate | pure logic: the host rule and the address table, the catalog's validation, sealing, the state machines, configuration |
| integration | every push, in the gate, against a real Postgres started by Testcontainers | the store suite on both adapters, identically; the same suite through a pooler in transaction mode; the migrations; one writer per refresh under contention |
| e2e | every push, in the gate | the whole server in process against the stubs: every route, a sign-in end to end, a call carried and streamed, two replicas over one database, the canary, and the threat model's tests ([[012-security-and-threat-model]]) |

The integration tier needs a container runtime. Where none answers,
its tests skip and the coverage floor fails for the packages only that
tier reaches, so a skipped tier is never a green gate.

A claim about custody or about what may be reached is accepted only
from the e2e tier. That tier holds two tests of its own. The canary
test of the agent guide, `TestNoCredentialLeavesButTowardItsConnector`,
plants a canary value as a pasted key, as the tokens the stub
authorization server issues and as a client secret, exercises every
route, and then searches every response, log line, span, call record
and database row for it. It finds each value in one place: at the stub
it belongs to, in the place it is sent. `TestEveryRouteIsExercised`
compares the routes the tier called with the OpenAPI document, so each
feature has an e2e test or the gate fails.

### Deploying

`deploy/base` holds a Deployment of two replicas, its Service, the
account it runs as, a disruption budget, and a network policy, and
nothing an installation chooses. `deploy/examples/generic` is an
overlay that renders with `kubectl kustomize`: the settings and an
example catalog as two ConfigMaps, the template of the Secrets an
operator applies by hand, and a pooler. Every host is under
`example.com`.

- **The container** runs as a user that is not root, with a read-only
  root file system, no capability, the runtime's default seccomp
  profile, and no token of the cluster's API. Liveness is `/livez`
  and readiness is `/readyz` ([[010-records-and-observability]]). The
  termination grace is 30 seconds, above the 25 the server gives its
  open requests.
- **The network rule** is the third layer of
  [[009-outbound-requests]]. Egress is allowed to the resolver, to the
  pooler and the database, to the authorizer, the issuer and the
  telemetry collector as the overlay names them, and to every address
  on port 443 except the private ranges of that spec's table. A catalog
  entry that names another port needs that port added by the overlay.
- **Two replicas** are interchangeable ([[001-architecture]]). The
  budget keeps one available through a rollout.
- **A pooler** in transaction mode stands in front of Postgres, so the
  replicas' pools do not each claim the database's connections. The
  server serves through `PONS_DATABASE_POOL_URL`. The migrations are
  embedded and run at start over `PONS_DATABASE_URL`, the direct
  connection, under the migrator's lock, so one replica runs them. The
  store uses nothing a pooler in transaction mode loses
  ([[005-store-and-sealing]]).

The example sets `PONS_OIDC_AUDIENCE` by name, which the gate's
identity rule reads, and never `PONS_DIAL_ALLOW_PRIVATE`. The tests of
the deploy tree read the files as written on every run of the gate. The
one that renders them needs `kubectl`, skips in the gate, and runs in
the `deploy` job.

### Release

A version tag is cut with `lateregate release vX.Y.Z` from a green
main: it moves the notes under `## Unreleased` in `CHANGELOG.md` to a
section for the version, tags and pushes. A tag whose commit has no
section is refused by the pre-push hook and by the release workflow.
Every section is written for whoever runs `ponsd` or calls its API.

The release workflow waits for the verify run of the tagged commit,
builds the image for both platforms, signs it, attests a bill of
materials and its provenance, archives `deploy/` with the image pinned
by digest, and creates the release from the changelog section. A third
workflow moves the gate's pin once a day when the whole bar passes on
the new version.

The repository was private at its first releases and became public on
2026-10-13, once the GitHub connector passed its check against the real
GitHub ([[013-github-connector]]). Only the runners of its workflows
changed at that moment, to hosted ones:
it is written as public from its first commit, and the gate's identity scan refuses a hosted
installation's own values in code, manifests and documents.

## Not in this spec

A command line client and client libraries. A Helm chart. Manifests of
any particular installation, which live with that installation. The
catalog entries of real services ([[006-catalog]]). What `/readyz`
answers ([[010-records-and-observability]]). The text of `SECURITY.md`
([[012-security-and-threat-model]]).

## Implementation status

Built: the layout of the table above but `deploy/`; `docs/`, written
by hand, its configuration reference not yet generated; `ponsd` with
`serve`, `check` and `version`; `internal/config`, which reads every variable of the table
once, `PONS_MAX_FORWARD_BYTES` included, and is the one package that
reads the environment; the gate's configuration, with `identity`
(`api_group: pons`, since Pons writes no resource under a group of its
own and a value under a hosted installation's domain would be one more
name of it), `postgres`, `license` and `cover`, the last exempting the
helper that starts the test containers; the `Makefile`, the two hooks,
the `verify` and `ci-gate bump` workflows, every job on a hosted runner
since the repository is public; the
community files; the `Dockerfile`; the stub issuer and the stub
authorizer over TLS on one authority, which panics, as
`net/http/httptest` does, when the system cannot make a key; the test
tiers, with the e2e tier beside `serve`.

The stub API, git host and authorization server are built beside the
issuer and the authorizer, with `stubs.Resolver`, which answers loopback
for every name under `example.com`, and `stubs.Permit` for the stubs'
listeners; the e2e tier hands both to the server's outside client
through its hooks. The git host skips the test that starts it, with the
reason, where `git` is not installed. The authorization server fetches no
client metadata document: a client id that is a URL is recorded.

The release workflow is built. A `v*` tag on a commit whose verify run
passed builds the image for both platforms, pushes it by digest, signs
it, checks that it reports the version the tag names, tags the digest,
creates the release from the tag's changelog section, and attaches the
bill of materials with a signed checksum. It attests the bill of
materials and the provenance only while the repository is public,
because GitHub keeps attestations for a private repository only on a
higher plan: v0.1.0 published nothing for that reason, and v0.1.1, of
2026-10-13, is the first release with an image. With no `deploy/`, a
release archives no manifests.

The stub connector is built beside them: a Model Context Protocol
server over streamable HTTP at `mcp.example.com`, of the current
revision, with five tools, a streamed answer, and a switch for each
answer of the table, the earlier revision's sessions, `GET` and
`DELETE` included, and a stream that waits for the test between events.

Remains: `deploy/`, and `docs/configuration.md` generated from the table, so the
`deploy` job of `verify` is not there yet; `TestReleaseWorkflowShape`.

| Criterion | State |
|---|---|
| the `gate` job | the gate passes locally with every package over the floor |
| `config.TestTableMatchesWhatIsRead`, `TestOnlyConfigReadsTheEnvironment` | written; the first reads the table of this spec until `docs/configuration.md` is generated |
| `config.TestErrorsNameTheVariableOnly` | written |
| `TestStartRefusals` | written |
| `TestCheckReports`, `TestCheckReportsWhatRemains` | written |
| `TestVersionIsStamped` | written |
| `stubs.TestConnectorSpeaksStreamableHTTP`, `stubs.TestEachSwitchChangesOneAnswer` | written |
| `stubs.TestAuthorizationServerRunsASignIn`, `stubs.TestAuthorizerRecordsEveryQuestion` | written, with `stubs.TestEachAuthSwitchChangesOneAnswer`, `stubs.TestAPIServesACodeHostsRoutes` and `stubs.TestGitHostServesGit` |
| `TestMemoryStore`, `TestPostgresStore`, `TestPostgresStoreThroughAPooler` | written |
| `TestEveryRouteIsExercised` | written, over the routes served |
| `TestNoCredentialLeavesButTowardItsConnector` | written for a key, issued tokens and a client secret |
| the `image` job | in `verify` |
| `TestEveryContainerIsConfined`, `TestDeployVariablesAreInTheTable`, `TestExampleRenders`, `TestExampleDeniesPrivateEgress` | not written: `deploy/` is not built |
| `TestReleaseWorkflowShape` | not written; the release workflow refuses a tag without a changelog section at its build job |
| the identity scan | passes |

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| `make check` passes on a fresh clone with the toolchain and a container runtime, and every package clears the coverage floor | the `gate` job of the verify workflow |
| The configuration table lists every variable the binary reads and none it does not, and no package of the module but `internal/config` reads the environment | `config.TestTableMatchesWhatIsRead`, `TestOnlyConfigReadsTheEnvironment` |
| A missing required variable and a value that does not parse each stop the start with the variable's name and never its value | `config.TestErrorsNameTheVariableOnly` |
| Each case of the table of refusals stops `serve` before it listens, and `PONS_PUBLIC_URL` over `http` is accepted on the memory store alone | `TestStartRefusals` |
| `ponsd check` fails on what `serve` refuses, reports the values not under the first sealing key, and reports `PONS_DIAL_ALLOW_PRIVATE` and the proxy with a zero status | `TestCheckReports`, `TestCheckReportsWhatRemains` |
| `ponsd version` prints the version, the commit and the date the build stamped | `TestVersionIsStamped` |
| The stub connector answers an initialize, a tool list, a tool call and a streamed call, and each switch changes one answer and nothing else | `stubs.TestConnectorSpeaksStreamableHTTP`, `stubs.TestEachSwitchChangesOneAnswer` |
| A sign-in runs end to end against the stub authorization server by each way Pons identifies itself, a spent refresh token is refused, and the stub authorizer records every question it was asked | `stubs.TestAuthorizationServerRunsASignIn`, `stubs.TestAuthorizerRecordsEveryQuestion` |
| The store suite passes on the memory adapter, on Postgres, and on Postgres through a pooler in transaction mode | `TestMemoryStore`, `TestPostgresStore`, `TestPostgresStoreThroughAPooler` |
| Every route of the OpenAPI document is called by the e2e tier | `TestEveryRouteIsExercised` |
| A canary planted as a key, as issued tokens and as a client secret is found at its stub alone | `TestNoCredentialLeavesButTowardItsConnector` |
| The image runs as a user that is not root, holds no shell, is under 40 MiB, and starts and answers with a read-only root file system and no capability | the `image` job of the verify workflow |
| Every container of `deploy/` is confined, every variable set there is in the table, no manifest sets `PONS_DIAL_ALLOW_PRIVATE`, and the example renders | `TestEveryContainerIsConfined`, `TestDeployVariablesAreInTheTable`, `TestExampleRenders` |
| The example's network rule excepts every block of the address table that a cluster can route from its egress on 443 | `TestExampleDeniesPrivateEgress` |
| A tag without a changelog section is refused by the pre-push hook and by the release workflow, whose jobs, order and permissions are held | the gate's own check, `TestReleaseWorkflowShape` |
| No file of the repository names an installation's hostname, account or credential | the gate's identity scan |
