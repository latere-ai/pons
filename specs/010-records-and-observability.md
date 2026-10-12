---
title: "Records and observability: the call record and its retention, metrics, traces, logs that hold no content, the probes"
status: drafted
track: core
depends_on:
  - specs/002-objects.md
  - specs/008-carrying-a-call.md
affects: [internal/carry/, internal/store/, internal/httpapi/, internal/dial/, cmd/ponsd/]
effort: medium
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Records and observability

## Overview

A person who connected a service wants to know what was done with it:
which caller used the connection, for which tool, when, and how it
ended. An operator wants to know whether Pons is healthy and why a call
was slow. This spec fixes the call record and how long it is kept, the
metrics, the traces and the logs, and the three probes. All of them
describe a call and none of them holds what the call said: no
argument, no result, no header value, no query string, no token and no
credential.

## Current state

Nothing is built.

The shared package `latere.ai/x/pkg/otel` wires logs, traces and
metrics in one call and exports them over OTLP when an endpoint is set,
and `latere.ai/x/pkg/health` serves the probes. A document parsing
service in a sibling project is the precedent for the rest: a record
of each unit of work that says what happened and never what was read,
metric labels whose number does not grow with tenants, and a test that
plants marked strings and searches every sink for them.

## Design

### The call record

Which requests to a connection's address leave a record, what
`method` and `tool` hold for each, and which `outcome` each way of
ending is, are [[008-carrying-a-call]]'s: in short, one record per
request whose connection was found, a refusal by the authorizer or a
limit included, as `denied`, at most once per subject and connection
per minute. A request refused before that names no connection, and a
`500` or `503` Pons raises itself is no call of the connector; both are
counted by the request metrics below and not recorded. A `502` or `504`
about the connector is recorded.

The fields are those of [[002-objects]]. How each is filled:

| Field | Filled from |
|---|---|
| `subject`, `session` | the verified caller; `session` as [[004-identity-and-authorization]] copies it |
| `owner`, `connector` | the connection as stored when the request arrived |
| `at` | when the request arrived |
| `duration_ms` | until the last byte of the answer was written, or the stream ended |
| `method`, `tool` | the request, as the carrier read it; `tool` at most 128 bytes |
| `effect` | the connector's marks for that tool, absent when the request names none |
| `outcome` | how the call ended ([[008-carrying-a-call]]) |
| `status` | the connector's last status, when it answered |
| `bytes_in`, `bytes_out` | the request body's size, and what was streamed back |

A record is written when the call ends, a streamed call included: when
the stream closes from either side or runs past its idle bound. It is
written after the last byte has been handed to the caller, so it never
holds a call open. The write has a context of its own, detached from
the request's, with a 5 second deadline, so a caller who leaves still
leaves a record. A failure to write is never the call's failure: it is
logged at warning level with the record's id and connection's id,
counted, and not retried. On shutdown the server's grace for open
requests covers the writes of the calls that end within it
([[011-distribution]]).

A record is read through `GET /connections/{id}/calls`, newest first,
by a caller allowed `connection.read` ([[003-api]]). It is not changed
after it is written. A deleted connection's records stay until their
retention passes, for the operator; no route reads them, since the
route needs the connection.

### Retention

`PONS_RECORDS_RETENTION`, a duration, `720h` by default, is how long a
record is kept. A value that is not a positive duration stops the
start. Every replica sweeps every 10 minutes: it removes records older
than the retention in batches of 1,000 until a batch removes fewer,
and then idempotency keys older than 24 hours the same way
([[005-store-and-sealing]]). Two replicas sweeping at once remove each
row once. A sweep that fails is logged and counted and tried again at
the next tick.

### Metrics

OpenTelemetry instruments, created from the meter provider
`otel.Bootstrap` installs, with the module's path as the
instrumentation scope. With no `OTEL_EXPORTER_OTLP_ENDPOINT` they are
recorded and discarded. `otel.Handler` adds the request metrics of
every route, named by its route template.

| Metric | Kind | Labels |
|---|---|---|
| `pons.calls` | counter | `connector`, `outcome`, `effect` |
| `pons.call.duration` | histogram, seconds | `connector`, `outcome` |
| `pons.refreshes` | counter | `outcome`: `ok`, `refused`, `failed`, `superseded` |
| `pons.signins` | counter | `outcome`: `connected`, `access_denied`, `sign_in_failed`, `flow_expired`, `invalid_code` |
| `pons.connections` | gauge | `state` |
| `pons.dial.refusals` | counter | `reason`, a name of the refusals table of [[009-outbound-requests]] |
| `pons.authorizer.calls` | histogram, seconds | `result`: `allow`, `deny`, `error` |
| `pons.records.write_failures` | counter | none |
| `pons.sweep.failures` | counter | `table` |

`connector` is the catalog name, and `added` for every connector a
person added, since their ids have no bound. `effect` is `read`,
`write` or `none`. No label holds an owner, a subject, a session, a
connection id, a tool, an account, a host or an address: their number
grows with use. Per-connection figures are read from the records.

`pons.refreshes` counts what [[007-sign-in]] does with the token
endpoint's answer: new tokens are `ok`, `invalid_grant` is `refused`,
anything else `failed`, and new tokens that lost to a reconnect are
`superseded`. `pons.signins` counts each flow's end once.
`pons.authorizer.calls` is fed by the `Observe` option of the
authorizer client. `pons.connections` is an observable gauge over a
count per state, read from the store with `CountByState`
([[005-store-and-sealing]]) at most once a minute per replica; every
replica reports the whole installation's figure, so it
is read with a maximum and never summed.

### Traces

Every request has a server span from `otel.Handler`, named by its
method and route template, so no id is in a span's name. That span
records the path and no query string. The probes record no span and no
request metric (`otel.WithSkip`).

A request to a connection's address opens one span, `pons.call`, under
the server span, with the attributes `pons.connection`,
`pons.connector`, `pons.method`, `pons.tool`, `pons.effect`,
`pons.outcome` and, when the connector answered, `pons.status`. The
outcome and the status are set when the call ends, a streamed one
included.

The outside client of [[009-outbound-requests]] sends no trace header
and is not wrapped with `otel.Transport`, whose client span would
record the full URL with its query. The carrier and the sign-in open a
span of their own for each request it carries, `pons.outbound`, with
the host, the status, the duration and the dialer's refusal or failure
name. The operator client, toward the authorizer and the issuer, is
wrapped with `otel.Transport` and carries the trace to them.

A span's error is the classified one: the code and the reason of the
error table of [[003-api]] or the refusal name of
[[009-outbound-requests]], never the text of an error from a
transport. Such a text can carry a whole URL: Go's `*url.Error` holds
the address it was asked for, query string included.

### Logs

Structured, through the logger `otel.Bootstrap` returns: JSON on
standard error, and over OTLP when an endpoint is set. A line written
while a request is served carries its trace and span ids.

A line holds identifiers, names, sizes, durations and outcomes, under a
fixed set of keys: `call`, `connection`, `connector`, `flow`,
`subject`, `method`, `tool`, `effect`, `outcome`, `status`, `code`,
`reason`, `host`, `route`, `table`, `key_id`, `count`, `bytes_in`,
`bytes_out`, `duration_ms` and `error`. The `session` claim goes to the
record alone. A line never holds an argument, a result, a header
value, a query string, a request or answer body, a token, a code, a
`state`, a verifier, a client secret or a credential. `error` is a
classified error as for a span. An error nobody classified is logged
with its text ([[003-api]]), after any URL in it has been cut to its
scheme, host and path.

| Line | Level |
|---|---|
| the start: which store, who decides, whether anything can be sealed, the dial switch and the proxy ([[011-distribution]]) | info, and warning for the switch |
| one per call when it ends: `call`, `connection`, `connector`, `outcome`, `status`, `duration_ms`, sizes | info |
| a refresh, a sign-in's end, a state a connection moved to | info |
| a record or a sweep that failed to write, a value no key opens | warning |
| an error nobody classified | error |

### Probes

Outside the base path, on the API's listener, with no token
([[003-api]]), served by `latere.ai/x/pkg/health` mounted path by path.

| Path | Answers |
|---|---|
| `/livez` | the process: `200` while it serves |
| `/readyz` | `200` when the store answers, a sealing key is present and the catalog was read; otherwise `503`, naming each check that failed |
| `/version` | the version, the commit and the build time |

The checks are `store` (the store's `Ready`, within 1 second),
`sealing` and `catalog`. The authorizer and the issuer are not checks:
every request fails closed while they are out of reach, and a restart
would not bring them back. A key rotation in progress leaves a server
ready. While `PONS_DIAL_ALLOW_PRIVATE` is set, a `200` from `/readyz`
carries the line `dial: private addresses allowed` after `ok`
([[009-outbound-requests]]). No probe answers with a host, an address
or a setting's value.

## Not in this spec

The record's route and its page ([[003-api]]). What the carrier
forwards and when a call ends ([[008-carrying-a-call]]). Dashboards
and alert rules, which belong to whoever operates an installation. An
audit log of reads and changes through the API, which the authorizer
can keep, since it is asked about every one. Export of records to
another system.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| A call through the stub connector leaves one record with every field of [[002-objects]] filled as the table says, and a refused token or an unknown id leaves none | `carry.TestACallLeavesOneRecord` |
| Each outcome of [[008-carrying-a-call]] is produced by a call that ends that way, and a record is written for it | `carry.TestEveryOutcomeIsRecorded` |
| A streamed call is recorded when the stream ends, from either side or by its idle bound, with the bytes and the duration of the whole stream, and a caller that leaves is recorded `canceled` | `carry.TestAStreamIsRecordedWhenItEnds` |
| A record that fails to write leaves the call's answer whole, counts one write failure and logs a warning without content | `carry.TestARecordFailureNeverFailsTheCall` |
| Records older than the retention are swept in batches and newer ones stay; idempotency keys older than 24 hours go too; two replicas sweep each row once | `TestRetentionSweep`, over both stores |
| A canary planted as a credential, an argument, a result, a header value, a query member, a `state` and a code appears in no record, log line, span attribute, span event or metric label, on success and on every outcome; an agent's session that calls every tool its allow admits obtains no credential, and its record names the session, the tool and the effect | `TestNoCredentialLeavesButTowardItsConnector`, with an in-memory span exporter, metric reader and log handler; `TestATrickedSessionObtainsNoCredential` |
| Every metric of the table exists with exactly its labels, and no label value is an id, an owner, a subject, a session, a tool or a host | `TestMetricLabelsAreBounded` |
| `pons.calls`, `pons.refreshes`, `pons.signins` and `pons.dial.refusals` each move by one for the event they count | `TestEachMetricCountsItsEvent` |
| A call has one `pons.call` span with the connection and the outcome, and no outbound span carries a URL with a query or a trace header to a connector | `carry.TestACallHasOneSpan`, `dial.TestNoCookieAndNoTraceHeaderLeave` |
| Every key a log call passes is in the fixed set | `TestLogKeysAreTheSet`, over the parsed call sites |
| An unclassified error whose text holds a URL with a query is logged with the query cut | `TestAnErrorsURLLosesItsQuery` |
| `/readyz` fails naming the store while the database is unreachable and recovers without a restart, fails naming `sealing` with no key, and carries the dial line while the switch is set | `TestReadiness` |
| The probes answer without a token, outside the base path, and record no span | `httpapi.TestProbes` |
