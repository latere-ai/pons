# Configuration

Every environment variable `ponsd` reads, its default, and what it does.
`ponsd` reads its configuration once, when it starts. A value that is
missing or does not parse stops the start with one message that names
every problem at once, each by its variable and never by its value,
since a variable may hold a secret. A variable set to the empty string
is unset.

`ponsd serve` and `ponsd check` read the same variables. `ponsd check`
also opens the store and the catalog as `serve` would, and serves
nothing ([Install](install.md#checking-an-installation)).

Durations are written the way Go writes them: `30s`, `5m`, `720h`. A
size is a whole number of bytes. A list is comma separated, and an empty
entry is dropped, except in `PONS_SEALING_KEYS`, where it refuses the
start.

## Addresses

| Variable | Default | What it is |
|---|---|---|
| `PONS_ADDR` | `:8080` | the address `ponsd` listens on, for the API and the probes |
| `PONS_PUBLIC_URL` | required | the URL other services and browsers reach `ponsd` at, with the path prefix a proxy in front adds, if any. Every address Pons hands out starts with it: a connection's `address` and `git_address`, the callback a service's sign-in returns to, and the client metadata document. An `http` or `https` URL with a host, and no user part, query or fragment. It must be `https` when a database is configured |
| `PONS_BASE_PATH` | `/v1` | the path every API route is under. A path that starts with a slash; `/` serves the routes at the root. The probes are always at the root |

## Store

| Variable | Default | What it is |
|---|---|---|
| `PONS_DATABASE_URL` | unset: the memory store | the direct address of the Postgres database. The schema is applied over it at start. Unset, `ponsd` keeps everything in the process, says so in its first log line, and loses it all on exit |
| `PONS_DATABASE_POOL_URL` | unset: serving uses `PONS_DATABASE_URL` | the address the server's connection pool opens, a pooler in transaction mode where you run one. Needs `PONS_DATABASE_URL`, since the schema is never applied through a pooler |
| `PONS_SEALING_KEYS` | required with a database | the keys every credential is sealed under: one or more 32-byte keys, each in base64, comma separated. The first seals; every key opens. A key listed twice is refused. [Install](install.md#sealing-keys) is how to make one and how to rotate. Without a database and without a key, the server starts, `/readyz` answers not ready, and a connect that would keep a credential answers `503 sealing_unavailable` |

## Identity

| Variable | Default | What it is |
|---|---|---|
| `PONS_OIDC_ISSUERS` | required | the OpenID Connect issuers whose tokens are accepted, each an `http` or `https` URL, listed once. At start `ponsd` reads each one's discovery document and key set; one that does not answer is named in the log, the server starts, and its keys are read when its first token arrives |
| `PONS_OIDC_AUDIENCE` | `pons` | the audiences a caller's token may name, one or more |
| `PONS_AUTHORIZER_URL` | unset: the owner policy | the endpoint asked what a caller may do. An `http` or `https` URL. [Writing an authorizer](authorizer.md) is the contract |
| `PONS_AUTHORIZER_TOKEN_FILE` | required with the URL | the path of a file holding the bearer `ponsd` sends the authorizer, read once at start. A file that is missing, unreadable or empty stops the start |

## Connectors and sign-in

| Variable | Default | What it is |
|---|---|---|
| `PONS_CATALOG_FILE` | unset: an empty catalog | the path of the [catalog](catalog.md), read and validated whole at start. A catalog that does not validate stops the start. Changing it is a restart |
| `PONS_RETURN_URLS` | unset: no sign-in can start | where a person's browser may be sent back to after a sign-in: exact URLs, and prefixes that end in `/`. A connect or a reconnect whose `return_to` is none of them is refused. No fragment |
| `PONS_CLIENT_NAME` | `Pons` | the name a person reads on another service's consent page, in the client metadata document and when Pons registers itself |
| `PONS_CLIENT_URI` | unset | a page about this installation, in the same documents. An `http` or `https` URL |

## Records

| Variable | Default | What it is |
|---|---|---|
| `PONS_RECORDS_RETENTION` | `720h` | how long a call record is kept. Every replica removes older records every ten minutes |

## Limits

| Variable | Default | What it is |
|---|---|---|
| `PONS_MAX_CONNECTIONS_PER_OWNER` | `100` | how many connections one owner may hold. An authorizer's allow may lower it for an owner and never raise it. A connect past it is `403 forbidden` |
| `PONS_CREATES_PER_MINUTE` | `10` | how many connects, reconnects and connector additions one caller may make in a minute, per replica. Past it, `429 rate_limited` |
| `PONS_MAX_INFLIGHT_PER_SUBJECT` | `32` | how many requests one caller may have in flight at a connection's addresses, per replica |
| `PONS_MAX_INFLIGHT` | `1024` | how many requests all callers may have in flight at the addresses, per replica |
| `PONS_MAX_REQUEST_BYTES` | `4194304` (4 MiB) | the largest body of a call to a connection's MCP address. Read and checked; it takes effect when the MCP address is served |
| `PONS_MAX_FORWARD_BYTES` | `2147483648` (2 GiB) | the largest body of a request to a forwarding or git address. The body streams, and one that runs past this is ended with `413 request_too_large` |
| `PONS_CALL_HEADER_TIMEOUT` | `30s` | how long Pons waits for the other service to start its answer. Past it, `504 connector_timeout` |
| `PONS_STREAM_IDLE_TIMEOUT` | `5m` | how long an answer may stream with nothing read before Pons ends it |

Every count is a whole number above zero; every duration and size is
above zero. One connection also has at most 16 requests in flight per
replica, and the API's own routes take a body of at most 64 KiB.

## Outbound requests

| Variable | Default | What it is |
|---|---|---|
| `PONS_OUTBOUND_PROXY` | unset: requests leave directly | an `http` or `https` proxy every request to another service goes through. It may carry a user and a password. The issuers and the authorizer are reached directly |
| `PONS_DIAL_ALLOW_PRIVATE` | `false` | `true` treats every address as public and allows every port, for a server run against test services on loopback. Never in production: it removes the rule that keeps a connector from reaching the installation's own network. `ponsd` warns at start, `ponsd check` reports it, and `/readyz` carries a line saying so. Takes `1`, `0`, `true` or `false` |

## Telemetry

`ponsd` writes its log as JSON lines on standard error. With
`OTEL_EXPORTER_OTLP_ENDPOINT` set it also exports logs, traces and
metrics over OTLP, configured by the standard OpenTelemetry variables, such as
`OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_RESOURCE_ATTRIBUTES` and
`OTEL_SDK_DISABLED`. These are the one exception to the `PONS_` prefix.

A certificate authority of your own, for an issuer or an authorizer
inside your network, is trusted the way the process trusts any, through
the system's roots.

## What refuses a start

`ponsd serve` stops before it listens, and `ponsd check` fails, with a
status that is not zero and a line naming the variable, when:

| Case | Why |
|---|---|
| `PONS_PUBLIC_URL` or `PONS_OIDC_ISSUERS` is unset | every address Pons hands out starts with the first, and every caller is verified against the second |
| a value does not parse | the line names the variable and the rule |
| a database is configured and `PONS_PUBLIC_URL` is not `https` | the callback and a connection's addresses carry codes and bearers |
| a database is configured and `PONS_SEALING_KEYS` is unset | a server that keeps credentials must be able to seal them |
| `PONS_DATABASE_POOL_URL` is set without `PONS_DATABASE_URL` | the schema is applied over the direct address alone |
| the database does not answer, or the schema could not be applied | within 30 seconds of the start |
| `PONS_AUTHORIZER_URL` is set and the token file is unset, unreadable or empty, or the token file is set without the URL | the endpoint needs its bearer, and a bearer needs its endpoint |
| the authorizer allows the probe | an endpoint that allows the reserved probe does not read the request ([Writing an authorizer](authorizer.md#failing-closed)) |
| the catalog does not validate | one line per problem, naming the entry and the member ([The catalog](catalog.md#validation)) |
| `PONS_ADDR` cannot be listened on | `serve` only; `ponsd check` does not listen |

An issuer or an authorizer that does not answer at start does not stop
it. The issuer's keys are read when its first token arrives, and every
request fails closed until the authorizer answers.
