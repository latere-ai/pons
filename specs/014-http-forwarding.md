---
title: "Plain HTTP and git through a connection: a forwarding address and a git address, the credential added, a path held to its connector, and a push held to the refs an allow names"
status: testing
track: core
depends_on:
  - specs/002-objects.md
  - specs/003-api.md
  - specs/004-identity-and-authorization.md
  - specs/006-catalog.md
  - specs/008-carrying-a-call.md
  - specs/009-outbound-requests.md
affects: [internal/carry/, internal/httpapi/, catalog/, authorizer/, api/]
effort: large
created: 2026-10-12
updated: 2026-10-13
author: changkun
---

# Plain HTTP and git through a connection

## Overview

Not every service runs a Model Context Protocol server, and the most
useful thing an agent does with a code host is not a tool call: it
clones a repository, works in it, pushes a branch, and calls the host's
API. A connector of kind `http` gives such a service a connection with
two addresses at Pons. The forwarding address carries plain HTTP to the
service's API. The git address, for a connector that names one, carries
git's smart HTTP protocol to the service's git host. A caller, usually
code in an agent's sandbox, uses both with its own token and never
holds the service's credential: Pons adds it on the way out.

This is the shape of the git proxy a hosted coding agent already uses:
the sandbox's git authenticates to the proxy with a scoped credential,
the proxy checks what the operation does, such as which branch a push
updates, and only then attaches the real token. Pons is that proxy, for
git and for the API beside it.

## Current state

Built; see Implementation status. The carrier of [[008-carrying-a-call]]
forwards a Model Context Protocol message, and this spec reuses its
steps, its header rules, its handling of a refused credential and its
record. What is new is what is read from a request: a path instead of a
tool, and for a push the refs it updates.

## Design

### The connector

A connector of kind `http` ([[006-catalog]]) gives:

| Member | Meaning |
|---|---|
| `url` | the API's base, such as `https://api.example.com`. Required |
| `git.url` | optional: the git host's base, such as `https://git.example.com` |
| `git.inject` | where the credential goes on a git request: `{scheme: bearer}` by default, or `{scheme: basic, username: <name>}`, which sends `Authorization: Basic` of the username and the token |
| `http.read_only` | optional: `METHOD path-glob` patterns of requests that only read, beyond `GET`, `HEAD` and `OPTIONS`: a method in capitals, one space, and a glob over the path below the address, which starts with a slash, such as `POST /search/*` |
| `http.pass` | optional: request headers passed toward the connector beside the carrier's own, such as an API version header. Not the credential's header, and not one the carrier sets or removes itself |
| `http.pass_back` | optional: globs of response header names passed back to the caller, matched without regard to case, such as `X-RateLimit-*` |

`hosts` must cover the host of `url` and of `git.url`. The credential
of an `oauth` or `client_credentials` connection is placed as
`Authorization: Bearer` on the forwarding address, and as `git.inject`
says on the git address. A `token` connection uses its `inject` on
both, unless `git.inject` is given.

### The addresses

| Address | Forwards to |
|---|---|
| `{base}/connections/{id}/http/{path}` | the connector's `url` joined with `{path}`, the query kept |
| `{base}/connections/{id}/git/{path}` | the connector's `git.url` joined with `{path}`, the query kept |

A connection of kind `http` carries both in its object as `address`
and `git_address`, the second only when its connector names `git.url`
([[002-objects]]). A request to the address of another kind is `409
wrong_kind`, as in [[008-carrying-a-call]].

**A path cannot leave its connector.** Before it is joined, `{path}` is
refused with `400 invalid_request` when it holds a `.` or `..`
segment, an empty segment, a trailing slash included, a backslash, an
encoded slash or backslash (`%2F`, `%5C`, in either case), an encoded
dot segment, or a control character, and when it is longer than 2048
bytes. The checks read the path as the caller escaped it, before any
router cleans or decodes it. An empty `{path}` is the connector's `url`
itself. The joined URL keeps the connector's scheme, host and port:
nothing in a request names another.

**The git address takes git's smart HTTP alone.** A request is served
only when it is a `GET` whose path ends in `/info/refs` with the query
`service` set to `git-upload-pack` or `git-receive-pack`, or a `POST`
whose path ends in `/git-upload-pack` or `/git-receive-pack`. Any other
request to the git address is `404 connection_not_found`, so the
address serves no web page of the git host. A connection whose
connector names no `git.url` has no git address: a request to it is
`409 wrong_kind`.

### One request

The steps of [[008-carrying-a-call]] in the same order, with three
differences.

1. **The body is not buffered.** It streams toward the connector as it
   arrives, up to `PONS_MAX_FORWARD_BYTES`, 2 GiB by default, past
   which the request is ended and answered `413 request_too_large`. A
   push is the one case read before it streams: below.
2. **The effect** is the request's own. On the forwarding address,
   `GET`, `HEAD` and `OPTIONS` read, a request matching
   `http.read_only` reads, and every other request writes. On the git
   address, `git-upload-pack` reads, which is a clone or a fetch, and
   `git-receive-pack` writes, which is a push.
3. **What the question names.** `connection.use` is asked with the
   method, the effect, and as `tool` the path without its query on the
   forwarding address, or `git-upload-pack` or `git-receive-pack` on
   the git address. A push also names `refs`, below
   ([[004-identity-and-authorization]]).

The allow's limits apply as for a call: `ReadOnly` refuses a write,
`Tools` holds the `tool` value to its globs, and `Refs` holds a push.

### A push names the refs it updates

A `git-receive-pack` request begins with the commands the push makes:
one pkt-line per ref, `<old id> <new id> <ref name>`, the first one
followed by a NUL and the client's capabilities, then a flush-pkt.
Pons reads the commands, at most 64 KiB and 1000 of them, and then
streams the rest of the request, the pack, untouched.

- The ref names go into the question as `refs` and into the record's
  count. A command whose new id is all zeros deletes its ref and is
  named the same way.
- Under an allow whose limits give `Refs`, globs over full ref names
  such as `refs/heads/agents/*`, a push that names any ref outside them
  is refused before a byte of the pack is sent: `403 forbidden` with
  `details.field` `refs`. Git shows the person the reason Pons gives.
- A request with a `Content-Encoding` is `400 invalid_request`. Git
  does not compress a push, so a compressed one is not git's.
- Commands that do not parse, or that run past either bound, are `400
  invalid_request`. A push from a shallow clone begins with `shallow`
  lines, which name no ref and are read past; a signed push is not taken.

A fetch and a clone are not read: what a caller may read is decided by
the question alone.

### Headers

Toward the connector, the forwarding address passes `Accept`,
`Accept-Encoding`, `Content-Type`, `Content-Length`, `If-None-Match`,
`If-Modified-Since`, `Range`, and the connector's own request headers
that the catalog lists in `http.pass`, such as an API version header.
The git address passes what git sends: `Accept`, `Accept-Encoding`,
`Content-Type`, `Content-Length`, `Content-Encoding` on a fetch, and
`Git-Protocol`. Everything else is removed as [[008-carrying-a-call]]
removes it, the caller's `Authorization` first.

A caller that names no `Accept-Encoding` is asked for none at the
connector, `identity`, so the transport undoes no coding of an answer
that passes through unread.

Back to the caller, both pass the status, the body, `Content-Type`,
`Content-Length`, `Content-Encoding`, `Cache-Control`, `ETag`,
`Last-Modified`, `Retry-After`, and headers matching `http.pass_back`
globs, such as a service's rate-limit headers. `Set-Cookie` and
`WWW-Authenticate` never pass.

**Links are rewritten to the address.** A `Link` header whose URLs
start with the connector's `url` has that prefix replaced with the
forwarding address, so a caller that follows the next page of a list
stays on Pons. A `Link` URL elsewhere is dropped from the header. This
is the one place Pons changes an answer, and it changes only that
header: a URL inside a body is passed as the connector wrote it.

**A redirect.** A `3xx` whose `Location`, resolved against the request
it answers, starts with the connector's `url`, or `git.url` on the git
address, at a boundary of its path, passes with that prefix rewritten
to the address. A `3xx` with no `Location`, such as `304`, passes as it
came. A `3xx` anywhere else is `502
connector_unavailable` with `details.reason` `redirect_elsewhere`: Pons
follows no redirect, and a caller that followed one would leave Pons
without the credential.

### When the connector refuses the credential

As [[008-carrying-a-call]] says, with one difference: the body is not
buffered, so a `401` is retried after a refresh only for a request with
no body. A request with a body answers the `401` the connector gave,
and the connection's next request uses the refreshed credential.

### The probe of a key

A key pasted for a connector of kind `http` is tried once before it is
stored ([[007-sign-in]]): one `GET` of the connector's `url` with the
key in its place, through the dialer, in 15 seconds. A `401` or a `403`
refuses it, `422 credential_refused`; no answer is `422
connector_unreachable`; any other status accepts it, since the service
answered without refusing the key, and many an API answers its base
with a `404`. The answer is kept nowhere.

### How a caller in a sandbox uses it

What an agent runtime does in a session's sandbox, as an example and
not as a requirement of Pons:

- **git:** `url.<git_address>/.insteadOf https://git.example.com/`, so
  `git clone https://git.example.com/acme/app` goes through Pons, and
  `http.<git_address>/.extraHeader` with `Authorization: Bearer` and
  the session's token for Pons, held as a placeholder that the
  sandbox's egress swaps in.
- **The API:** an environment variable naming the forwarding address,
  which the agent's tools and instructions use in place of the API's
  own host, with the same bearer.

The sandbox holds no credential of the service, and the session's
token for Pons opens nothing at any other service.

### What is recorded

One record per request, as [[010-records-and-observability]] says.
`method` is the HTTP method and `tool` is the path without its query or
the git service. A push's record also counts its refs, in a column
`refs`, and holds no ref name.

## Implementation status

Built in `internal/carry`, served before the router of `internal/httpapi`
so the path is judged as the caller escaped it: both addresses, the path
rules, the four requests of the git address, the effect, the question
with `method`, `tool`, `effect` and `refs`, a push's commands read
before its pack and held to `Refs`, the body streamed and bounded by
`PONS_MAX_FORWARD_BYTES`, the headers each way, `Link` and `Location`
moved under the address, a `3xx` elsewhere as `redirect_elsewhere`, a
refused credential, the scope challenge, records with the count of
refs, and the probe of a key. A body that runs past its bound after the
connection was found is recorded `denied`, as a bound Pons holds.

| Criterion | State |
|---|---|
| `carry.TestAForwardedPathStaysOnItsConnector` | written |
| `carry.TestTheGitAddressServesGitAlone` | written; skipped with its reason where `git` is not installed |
| `TestCloneThroughTheGitAddress` | written, in the e2e tier, with a real `git` |
| `carry.TestAPushIsHeldToItsRefs` | written, with a real `git` |
| `carry.TestTheEffectOfAForwardedRequest` | written |
| `carry.TestAForwardedBodyStreams` | written |
| `carry.TestLinksComeBackToTheAddress` | written |
| `carry.TestARedirectStaysOnItsConnector` | written |
| `carry.TestForwardedHeaders` | written |
| `carry.TestARefusedForwardedRequest` | written |
| `carry.TestForwardedRequestsAreRecorded` | written |

## Not in this spec

A change held for its owner's confirmation one request at a time;
reading a request body to decide its effect, such as a GraphQL query
or mutation, which is a write here; following a redirect to another
host, such as an archive download; the git protocol over SSH.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| A path with a dot segment, an empty segment, an encoded slash, backslash or dot, a control character, or over 2048 bytes is refused before the connection is loaded, and no request leaves for another host | `carry.TestAForwardedPathStaysOnItsConnector` |
| The git address serves the four smart HTTP requests and answers every other path `404` | `carry.TestTheGitAddressServesGitAlone` |
| A clone and a fetch through the git address of a connection to the stub git host succeed with the credential placed as `git.inject` says, and the caller's token never reaches the stub | `TestCloneThroughTheGitAddress` |
| A push naming a ref outside `Refs` is refused before any of the pack is sent, a push inside it lands, a deletion is held to the same rule, and a compressed push is refused | `carry.TestAPushIsHeldToItsRefs` |
| `GET`, `HEAD`, `OPTIONS` and an `http.read_only` match read, every other method writes, and `ReadOnly` refuses a write | `carry.TestTheEffectOfAForwardedRequest` |
| A body streams without being buffered, and one past `PONS_MAX_FORWARD_BYTES` ends with `413` | `carry.TestAForwardedBodyStreams` |
| A `Link` header's URLs under the connector's `url` come back under the forwarding address and others are dropped; a body's URLs are unchanged | `carry.TestLinksComeBackToTheAddress` |
| A `3xx` within the connector comes back rewritten, and one elsewhere is `502` with `redirect_elsewhere` | `carry.TestARedirectStaysOnItsConnector` |
| Only the listed headers pass each way, and `Set-Cookie` and `WWW-Authenticate` never do | `carry.TestForwardedHeaders` |
| A `401` to a request with no body is retried once after a refresh, and one to a request with a body is answered as it came | `carry.TestARefusedForwardedRequest` |
| Each forwarded request leaves one record with its method, its path or git service, and a push its count of refs | `carry.TestForwardedRequestsAreRecorded` |
