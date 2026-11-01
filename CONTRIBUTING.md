# Contributing

Thanks for looking. This file is for people and agents changing Pons.
Users read the [README](README.md) and [`docs/`](docs/README.md); the
design, and the reasoning behind each decision, lives in
[`specs/`](specs/README.md).

## Getting set up

You need Go 1.27 or newer, `git`, and a container runtime that
Testcontainers can reach, Docker or Podman. Then:

```sh
make        # the quality gate
make build  # out/ponsd
make run    # builds and starts the server on the memory store
```

`make run` sets `PONS_PUBLIC_URL` to `http://localhost:8080` and reads
the rest of the configuration from your environment, so set
`PONS_OIDC_ISSUERS` first. [Running it locally](docs/local.md) starts an
issuer to point it at.

The gate starts Postgres, and PgBouncer in front of it, in containers
for the store's suite. Where no container runtime answers, that suite
cannot run, and the coverage floor fails for the packages only it
reaches: a skipped suite is never a green gate. Under Podman, where
Testcontainers' reaper container cannot start, the helper turns the reaper
off itself. It labels every container it starts, and each start first
removes the ones a killed test binary left behind. The tests of the git
address run a real `git`, and skip, saying so, where it is not installed.

Install the hooks once with `make hooks`. They run formatting and license
checks before a commit and the linter before a push, so you see a finding
before CI does.

## Sending a change

Fork the repository, work on a branch, and open a pull request. Keep one
logical change per commit, stage the files explicitly, and write the
subject as `scope: what changed`, for whoever reads the log. The pipeline
runs the gate on every push and pull request.

If you are planning something large, open an issue first. A feature
starts as a spec with acceptance criteria that are testable sentences;
a design that lands without one is harder to review than one that
arrives with the reasoning attached. Small fixes need no spec.

A change to a behavior a spec describes updates that spec in the same
change: its implementation status, its status, and its Outcome once it
is complete. A change to the API, the catalog format, a configuration
variable, or the authorizer's vocabulary or limits also updates
[`docs/`](docs/README.md), and [`api/openapi.yaml`](api/openapi.yaml)
where it applies. A change someone running `ponsd` would notice gets a
line under `## Unreleased` in [`CHANGELOG.md`](CHANGELOG.md), written for
them; a `v*` tag without a section there is refused.

## The bar

`make` runs the whole gate (`go tool lateregate`): formatting, the linter,
modernization, known vulnerabilities, the suite under the race detector,
per-package coverage at 90% or more, the license notice, the identity and
database declarations, and the spec tree. `go tool lateregate list` names
the gates and `go tool lateregate <name>` runs one. `make specs` checks
the spec tree alone, and `make openapi` the tests that hold the router to
the OpenAPI document.

A bug fix carries a test that fails without it. A change that lowers a
threshold or adds a waiver records the reason in `.lateregate.yaml`, so the
exception is reviewable rather than invisible.

## The test tiers

`go test ./...` runs all three, and the gate runs them once with coverage
taken over every package.

| Tier | What it proves | Needs |
|---|---|---|
| unit | pure logic: the host rule, the catalog's validation, sealing, the state machines, configuration | Go |
| integration | the store's suite on the memory adapter and on Postgres, directly and through a pooler in transaction mode; the migrations; one writer per refresh under contention | a container runtime |
| end to end | the whole server in process against the stub services of [`test/stubs`](test/stubs): every route, a sign-in, a call forwarded and streamed, a clone and a push, two replicas over one database | `git` for the git tests |

The stubs are an issuer, an authorizer, an authorization server, an API
and a git host, each on loopback over TLS with a certificate from one
authority the package makes. The package is public, so a consumer's own
tests can start them.

### A further check against the real Google

`TestGoogleRealForwarding` (`cmd/ponsd/google_live_test.go`) runs the
Gmail, Google Calendar and Google Drive entries of
[`specs/015-google-connectors.md`](specs/015-google-connectors.md)
against the real Google instead of a stub. It is skipped unless
`GOOGLE_LIVE_CLIENT_ID`, `GOOGLE_LIVE_CLIENT_SECRET` and
`GOOGLE_LIVE_REFRESH_TOKEN` are set, so neither `make` nor CI runs it.

Running it needs an OAuth 2.0 client of type Web application in a
Google Cloud project of your own, with the Gmail, Calendar and Drive
APIs enabled, and a refresh token for a test Google account that
granted the union of the three entries' `scopes` (spec 015 names them)
in one consent. Mint the refresh token by sending that account through
the client's authorization URL with `access_type=offline` and
`prompt=consent`, and the union of those scopes, then exchanging the
returned code at Google's token endpoint for a refresh token; the test
sets `GOOGLE_CLIENT_SECRET` itself, so you set only the three variables
below.

```sh
GOOGLE_LIVE_CLIENT_ID=<your client id> \
GOOGLE_LIVE_CLIENT_SECRET=<your client secret> \
GOOGLE_LIVE_REFRESH_TOKEN=<the test account's refresh token> \
  go test ./cmd/ponsd -run TestGoogleRealForwarding -v
```

It proves the forwarding path for real: the credential refreshes at
Google's token endpoint on the first call, then a read-only call
reaches each of Gmail, Calendar and Drive, and a write each connector's
allow does not admit, `gmail.compose`'s own send included, is refused
by the authorizer's `requests` limit before it ever reaches Google. It
does not run the sign-in and does not disconnect or revoke at Google,
which still need a person at a browser.

## Two rules that are not style

**A credential never leaves.** No route, record, log line, error or test
fixture carries a credential's value. A claim that one does not is proven
by a test that plants a canary value and searches every output for it,
and a new route joins that test.

**An address is hostile until shown otherwise.** Every request to an
address a catalog entry, a person or another service's document named
goes through `internal/dial`. Nothing else in the tree builds an HTTP
client, a transport or a dialer, and a test over the call sites holds
that. Only `internal/config` reads the environment.

## Where things go

| Path | What lives there |
|---|---|
| `cmd/ponsd/` | the server and its commands, `serve`, `check` and `version`, with the end-to-end tier beside it |
| `api/` | the HTTP contract, `openapi.yaml`. Public |
| `authorizer/` | the action vocabulary and the limits of an allow. Public |
| `catalog/` | the catalog file's types, its validation and the host rule. Public |
| `internal/access/` | token verification, the authorizer client and the owner policy |
| `internal/httpapi/` | the routes, the errors and the probes |
| `internal/carry/` | the forwarding and git addresses |
| `internal/signin/` | discovery, the sign-in, refresh and revocation |
| `internal/store/` | the store, sealing, and the memory and Postgres adapters |
| `internal/dial/` | the one dialer every outbound request goes through |
| `internal/config/` | configuration, read once |
| `test/stubs/` | the stub services the tests run against |
| `specs/` | one spec per component, in build order in [`specs/README.md`](specs/README.md) |

The public packages, `api`, `authorizer` and `catalog`, change additively
within a major version of the module: a change keeps every existing call
site compiling, or the CHANGELOG names the break.

## Reporting a vulnerability

Do not open an issue. [`SECURITY.md`](SECURITY.md) says where to send it.
