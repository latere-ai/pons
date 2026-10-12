# Contributing

This file is for people and agents changing Pons. Users read the
[README](README.md); the design and the reasoning behind it live in
[`specs/`](specs/README.md).

## Getting set up

You need Go 1.27 or newer, `git`, and a container runtime that
Testcontainers can reach, Docker or Podman. Then:

```sh
make        # the quality gate
make build  # out/ponsd
make run    # the server on the memory store
```

The gate starts Postgres in a container for the store's suite. Where no
container runtime answers, that suite cannot run, and the coverage floor
fails for the packages only it reaches: a skipped suite is never a green
gate.

Install the hooks once with `make hooks`. They run formatting and license
checks before a commit and the linter before a push, so you see a finding
before CI does.

## Sending a change

Keep one logical change per commit, stage the files explicitly, and write
the subject as `scope: what changed`, for whoever reads the log. The
pipeline runs the gate on every push and pull request.

A change to a behavior a spec describes updates that spec in the same
change: its implementation status, its status, and its Outcome once it
is complete. If you are planning something large, write the spec first.
A design that lands without one is harder to review than one that
arrives with the reasoning attached.

## The bar

`make` runs the whole gate (`go tool lateregate`): formatting, the linter,
modernization, known vulnerabilities, the suite under the race detector,
per-package coverage at 90% or more, the license notice, the identity and
database declarations, and the spec tree. `go tool lateregate list` names
the gates and `go tool lateregate <name>` runs one.

A bug fix carries a test that fails without it. A change that lowers a
threshold or adds a waiver records the reason in `.lateregate.yaml`, so the
exception is reviewable rather than invisible.

## Two rules that are not style

**A credential never leaves.** No route, record, log line, error or test
fixture carries a credential's value. A claim that one does not is proven
by a test that plants a canary value and searches every output for it,
and a new route joins that test.

**An address is hostile until shown otherwise.** Every request to an
address a catalog entry, a person or another service's document named
goes through `internal/dial`. Nothing else in the tree builds an HTTP
client, a transport or a dialer, and a test over the call sites holds
that.

## Where things go

| Path | What lives there |
|---|---|
| `api/` | the HTTP contract, `openapi.yaml`. Public |
| `authorizer/` | the action vocabulary and the limits of an allow. Public |
| `catalog/` | the catalog file's types and its validation. Public |
| `internal/` | everything else, one package per concern |
| `cmd/ponsd/` | the server |
| `test/stubs/` | the stub services the tests run against |
| `specs/` | one spec per component |
