---
title: "Plain HTTP through a connection: a forwarding address, the credential added, and a change held for its owner's confirmation"
status: vague
track: core
depends_on:
  - specs/003-api.md
  - specs/008-carrying-a-call.md
  - specs/009-outbound-requests.md
affects: [internal/carry/, internal/httpapi/, catalog/]
effort: large
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Plain HTTP through a connection

## Overview

Not every service runs a Model Context Protocol server. Many take an
API key and answer plain HTTP. A connector of kind `http` gives such a
service a connection, and code that holds no key calls the service
through an address at Pons. This spec is a problem statement and a
proposed shape. The questions at its end are answered before it is a
design.

## Current state

Nothing is built. The carrier of [[008-carrying-a-call]] forwards one
kind of request, a Model Context Protocol message. A sandbox control
plane in a sibling project swaps a placeholder for a secret at its
egress gateway and has drafted holding a request for its owner's
confirmation by method and path, which is the precedent for the last
part below.

## Design

A proposed shape, not yet a design.

- **The address** is `{base}/connections/{id}/http/{path...}`. A
  request to it is forwarded to the connector's `url` joined with the
  path, with the query kept, the caller's token removed and the
  credential placed where the connector takes it. Everything else is
  the carrier's: verification, the question, the dialer, the record.
- **The effect is the method's.** `GET` and `HEAD` read. Every other
  method changes something, unless the catalog marks a method and a
  path glob as reading, as it marks tools.
- **A change may be held.** An allow may say that a change needs its
  owner's confirmation. Pons then refuses the request with `403
  confirmation_required`, records what was asked by method and path,
  and the owner, with a credential of their own, places a one-shot
  allowance for exactly that method and path. The caller sends the
  request again.
- **A path cannot leave its connector.** The path is cleaned before it
  is joined, an encoded slash or dot segment is refused, and the host
  is always the connector's.

## Open questions

1. Whether a tool that needs the service's real host, such as git, is
   served from here by a secret another system keeps fresh, or is out
   of scope for Pons altogether.
2. Whether the body of a request is ever read to decide its effect, for
   a service whose every call is a `POST`.
3. How a caller that is not a person's own client learns that a request
   is held, and who may place the allowance.
4. Whether an answer is streamed without bound or held to a size.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The questions above are answered and this spec is rewritten as a design before any of it is built | review |
