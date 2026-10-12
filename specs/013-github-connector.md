---
title: "A code host's connector: an app a person installs on chosen repositories, joined with the sign-in in one redirect"
status: vague
track: core
depends_on:
  - specs/006-catalog.md
  - specs/007-sign-in.md
affects: [catalog/, internal/signin/, internal/httpapi/]
effort: medium
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# A code host's connector

## Overview

Most connectors need nothing of their own: a catalog entry and the
sign-in of [[007-sign-in]]. A code host such as GitHub differs in one
step. Its access is an app a person installs on an account, choosing
the repositories it may reach, and the person's sign-in is a second
grant on top of the installation. This spec is a problem statement and
a proposed shape. The questions at its end are answered before it is a
design.

## Current state

Nothing is built. The precedent is a connector an identity provider
carried for one code host: it started the installation with the
sign-in requested in the same redirect, recorded the installation with
its account and repositories, and kept a token per person with a sealed
refresh token. Its flow is known to work. Its code is not carried over,
since the token custody it built by hand is what the connection store
does for every connector.

## Design

A proposed shape, not yet a design.

- **One more `auth.type`, `app`,** beside `oauth`. Its catalog members
  are the app's slug, its client id and secret, and the address the
  installation starts at. The connect answers an `authorization_url`
  that is the installation page, and the callback receives a code and
  an installation id together. From there the flow is
  [[007-sign-in]]'s: the same `state`, the same seal, the same confirm.
- **The connection carries what the installation covers:** the account
  it is on and whether it reaches all repositories or a chosen list.
  Pons reads it from the service with a token it signs as the app, and
  shows it as the connection's `account` and one more member,
  `resources`.
- **The credential is the person's token,** refreshed like any other.
  A token signed as the app is made when it is needed and stored
  nowhere.
- **A person who already installed the app** is not sent to install it
  again: the sign-in alone is enough, and the connection finds the
  installations that person can reach.

## Open questions

1. Whether the code host's own MCP server accepts a token of an app's
   user. If it does not, this connector's first use is plain HTTP and
   git, which need [[014-http-forwarding]] and more.
2. Whether `resources` is a member of every connection, empty for most,
   or of this type alone.
3. Whether an organization's installation is one connection its owner
   organization holds, or one per member who signs in.
4. What a removed installation looks like to a connection:
   `needs_reconnect` with a reason of its own, learned from a refused
   call or from an event the service sends.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The questions above are answered and this spec is rewritten as a design before any of it is built | review |
