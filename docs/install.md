# Install

What an installation of Pons needs, and how to run, check and upgrade
it. [Running it locally](local.md) is the shorter path when you only
want to try it; this page is for an installation that keeps what it
holds.

## What you need

- **The server**, as the image `ghcr.io/latere-ai/ponsd:<tag>` or a
  binary you build.
- **An OpenID Connect issuer** whose tokens name the audience `pons`, or
  one you list in `PONS_OIDC_AUDIENCE`. Every API request carries a
  token from it. Pons has no login and no API key of its own.
- **A public `https` address** that reaches `ponsd`, `PONS_PUBLIC_URL`.
  Callers reach connections there, and a person's browser comes back
  there from another service's sign-in.
- **Postgres 16 or newer**, and optionally a pooler in transaction mode
  in front of it.
- **A sealing key**, kept wherever your secrets live.

An [authorizer](authorizer.md), a [catalog](catalog.md) and the return
addresses of your app are optional, and each is one variable.
[Configuration](configuration.md) lists every variable.

## The server

Every release publishes the image `ghcr.io/latere-ai/ponsd:<tag>`, where
the tag is the release's git tag, such as `v0.1.1`, for linux/amd64 and
linux/arm64. It holds `ponsd` and the certificate roots it verifies
other services against, on a distroless base: no shell, no package
manager, the numeric user `65532`. `ponsd` starts no other program and
writes no file, so it runs with a read-only root file system and every
capability dropped. It listens on port 8080, and its default command is
`serve`.

```sh
podman run --rm ghcr.io/latere-ai/ponsd:v0.1.1 version
```

`ponsd` takes one command and no flags, and is configured by its
environment:

| Command | What it does |
|---|---|
| `ponsd serve` | applies the schema, reads the catalog, and serves until it is stopped |
| `ponsd check` | reads everything `serve` reads, serves nothing, and prints one line per finding |
| `ponsd version` | prints the version, the commit and the date of the build |

To build it yourself from a clone, `make build` writes `out/ponsd`, and
`podman build -t ponsd .` builds the same image the release does; it
reports the version `dev` unless you pass the build arguments the
`Dockerfile` names, `VERSION`, `COMMIT` and `DATE`.

## Postgres

`PONS_DATABASE_URL` is the direct address of the database. `ponsd`
applies its schema over it at start, under a lock, so of several
replicas starting together one applies it and the others wait. A server
refuses to start against a schema a newer release wrote, and against
one a failed migration left half applied.

Where a pooler stands in front of Postgres, such as PgBouncer in
transaction mode, `PONS_DATABASE_POOL_URL` is its address, and the
server serves through it. The schema is still applied over
`PONS_DATABASE_URL`, since the migration's lock does not survive a
transaction-mode pooler. Nothing the server does needs a session that
outlives a transaction.

With a database configured, `ponsd` also requires `PONS_PUBLIC_URL` to
be `https` and `PONS_SEALING_KEYS` to be set. Without one, it keeps
everything in memory and loses it on exit, which suits a trial and
nothing else.

## Sealing keys

Every credential is sealed under a data key of its own, and each data
key is wrapped by the first of `PONS_SEALING_KEYS`. The database never
holds a sealing key, so a copy of the database opens nothing. A key is
32 random bytes in base64:

```sh
openssl rand -base64 32
```

Keep the key where your other secrets live, and hand it to `ponsd` as
the variable. Losing every key loses every credential: the connections
remain, and each person connects again.

To rotate, put the new key first and keep the old one after it,
`PONS_SEALING_KEYS=<new>,<old>`, and restart. At start the server
rewraps every sealed value under the new key in the background, and
logs how many it moved. `ponsd check` shows how far it has come, per
table:

```text
sealing: credentials: 0 not under the first key, 0 under no listed key
sealing: flows: 0 not under the first key, 0 under no listed key
sealing: registrations: 0 not under the first key, 0 under no listed key
```

When every table says `0 not under the first key`, remove the old key
and restart. A value under no listed key fails the check, which is what
removing a key too early looks like: put the key back.

## Sign-in

A connector whose people sign in sends them to the other service and
back to Pons. Two addresses matter:

- **The callback**, `{PONS_PUBLIC_URL}{PONS_BASE_PATH}/callback`, such as
  `https://pons.example.com/v1/callback`. Register it, exactly, as the
  redirect address of the OAuth application you create at each service.
- **Your app's return address**, listed in `PONS_RETURN_URLS`. After
  the callback, Pons sends the browser there with the connection's id
  and a one-time code, and your app confirms the connection
  ([API](api.md#by-signing-in)). Without the variable, no
  sign-in can start.

A service that identifies its clients by a URL reads Pons's client
metadata document at `{PONS_PUBLIC_URL}{PONS_BASE_PATH}/client`. It
names the installation by `PONS_CLIENT_NAME` and `PONS_CLIENT_URI`.

## Probes

Three routes at the root of the listener, outside `PONS_BASE_PATH`, take
no token:

| Route | Answers |
|---|---|
| `GET /livez` | `ok` while the process serves |
| `GET /readyz` | `ok` when the store answers, a sealing key is set, and the catalog was read; otherwise `503` with what is not ready, such as `not ready: sealing: no sealing key`. With `PONS_DIAL_ALLOW_PRIVATE` set, a ready answer carries a second line saying so |
| `GET /version` | the version, the commit and the build time, as JSON |

## Checking an installation

`ponsd check` runs with the same environment as `serve` and answers
whether that server would start, without serving. It reads the catalog,
applies the schema, reads the issuers' keys, and asks the authorizer the
probe. It exits `1` on anything `serve` would refuse before it listens,
and on a sealed value no listed key opens.

```sh
podman run --rm \
  -e PONS_PUBLIC_URL=https://pons.example.com \
  -e PONS_OIDC_ISSUERS=https://login.example.com \
  -e PONS_CATALOG_FILE=/etc/pons/catalog.yaml \
  -v "$PWD/catalog.yaml:/etc/pons/catalog.yaml:ro" \
  -e PONS_DATABASE_URL -e PONS_SEALING_KEYS \
  ghcr.io/latere-ai/ponsd:v0.1.1 check
```

```text
configuration: ok
catalog: 2 connectors
decides: owner policy
sealing: credentials: 0 not under the first key, 0 under no listed key
sealing: flows: 0 not under the first key, 0 under no listed key
sealing: registrations: 0 not under the first key, 0 under no listed key
```

`decides` says who answers what a caller may do: `authorizer`, or
`owner policy` when `PONS_AUTHORIZER_URL` is unset. The `sealing` lines
need a database, and are absent on the memory store. A line also
appears when `PONS_DIAL_ALLOW_PRIVATE` or `PONS_OUTBOUND_PROXY` is set.

## The network

`ponsd` listens on one port, `PONS_ADDR`, for the API, the connections'
addresses and the probes. A proxy in front terminates TLS and forwards
the path unchanged.

Outbound, it reaches four kinds of address:

- the issuers and the authorizer, at the addresses you configured;
- the database, or the pooler;
- an OpenTelemetry collector, if you configure one;
- the services of the catalog and their sign-in, on public addresses.

Toward a service, Pons connects only over `https`, to a name it resolves
to public addresses alone, on port 443 or a port the service's catalog
entry names. A name that answers with any private, loopback or
link-local address is refused whole. A network rule for the deployment
can match that: allow port 443 to the internet, except the private
ranges, beside the first three.

## Several replicas

Replicas are interchangeable over one database. A credential near its
end is refreshed by one replica at a time, so two replicas never spend
the same refresh token. Every replica removes old call records and the
sign-ins that ran out. The
limits per minute and in flight of [Configuration](configuration.md#limits)
are counted per replica.

## Stopping and upgrading

On `SIGINT` or `SIGTERM`, `ponsd` stops accepting connections, gives
open requests 25 seconds to finish, and then closes the streams left.
Give the container a termination grace above that, such as 30 seconds.

Upgrading is running the next release's image. The tag equals the git
tag, and `ponsd version` says which one runs. The new release applies
its schema at start; the [changelog](../CHANGELOG.md) says what changed
for whoever runs `ponsd`.
