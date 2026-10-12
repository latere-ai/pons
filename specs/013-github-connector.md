---
title: "A code host's connector: GitHub through a GitHub App, signed in like any connector, with the account read once and a link to choose repositories"
status: drafted
track: core
depends_on:
  - specs/006-catalog.md
  - specs/007-sign-in.md
  - specs/008-carrying-a-call.md
affects: [catalog/, internal/signin/, internal/httpapi/]
effort: medium
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# A code host's connector

## Overview

GitHub is the first connector an installation is expected to offer,
and it needs almost nothing of its own. A GitHub App's user sign-in is
an OAuth authorization code flow with a client the operator registered,
so the entry is an ordinary `oauth` connector with `discovery: none`
([[006-catalog]], [[007-sign-in]]), and GitHub's own Model Context
Protocol server is the address its calls are carried to
([[008-carrying-a-call]]).

Two things differ from the general case, and this spec adds a catalog
member for each: the account a connection acts as is read from an API
after the sign-in, since GitHub issues no identity token, and a GitHub
App reaches only the repositories it is installed on, so a person needs
a link to install it or to choose repositories.

## Current state

Nothing is built. The precedent is a connector an identity provider
carried for one GitHub App: it sent the person to GitHub's authorize
endpoint with the App's client id, exchanged the code, kept the
person's token with a sealed refresh token, and read the person's
installations with that token. Its flow works in production with the
same App an installation can reuse. Its code is not carried over, since
the token custody it built by hand is what the store does for every
connector ([[005-store-and-sealing]]). Three of GitHub's habits it
handled are written down below.

The protocol question this spec once left open is not settled by
GitHub's documentation: whether GitHub's remote MCP server accepts the
user token of a GitHub App, as opposed to a personal token or a token
of an OAuth App. A maintainer of that server has said in its issue
tracker that a GitHub App's user token works for the repositories the
App is installed on. It is checked against the real server before the
entry ships (acceptance criteria), and the fallback is named under
[If GitHub's server refuses the token](#if-githubs-server-refuses-the-token).

## Design

### The entry

```yaml
connectors:
  - name: github
    title: GitHub
    description: Read and change the repositories, issues and pull requests you choose.
    icon: https://github.githubassets.com/favicons/favicon.svg
    kind: mcp
    url: https://api.githubcopilot.com/mcp/
    hosts: ["api.githubcopilot.com", "api.github.com"]
    auth:
      type: oauth
      discovery: none
      authorize_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
      client: {id: Iv23exampleclientid, secret: {env: GITHUB_APP_CLIENT_SECRET}}
      resource: false
      account: {url: https://api.github.com/user, field: login}
    links:
      manage: https://github.com/apps/{app slug}/installations/new
    tools:
      read_only: ["get_*", "list_*", "search_*"]
```

- **`discovery: none`.** GitHub publishes no authorization server
  metadata for a GitHub App's client, so the entry gives the two
  endpoints. GitHub sends no `iss` in its answer. The rule of
  [[007-sign-in]] accepts an answer without `iss` because the catalog
  names this server by its endpoints, and only the operator writes the
  catalog.
- **No revocation.** GitHub's way to revoke a user's token needs the
  App's client secret as Basic credentials on a different API host, not
  the form of RFC 7009, so the entry gives no `revoke_url`. A
  disconnect deletes the credential and does not revoke it at GitHub.
  The person can revoke the App's access in their GitHub settings, and
  the connection's page says so.
- **`resource: false`.** GitHub's token endpoint ignores the member;
  sending it changes nothing, and leaving it out keeps the request to
  what GitHub documents.
- **No scopes.** A GitHub App's token carries no scopes: what it may do
  is the App's permissions, crossed with what the person may do, on the
  repositories the App is installed on.
- **`hosts`.** The MCP server's host, and GitHub's API host for the one
  read of the account. The token endpoint is recorded with the
  credential and is no member of `hosts` ([[009-outbound-requests]]).

### Two catalog members

Both are optional on any `oauth` entry, and validated with the rest of
the catalog ([[006-catalog]]).

| Member | Meaning |
|---|---|
| `auth.account` | `{url, field}`. After the code exchange and before the confirm, Pons sends one `GET` to `url` with the new access token, through the dialer, and keeps the string at the top-level JSON member `field` as the connection's `account`. `url` must be https and its host must match `hosts`, so the token goes nowhere a call would not take it. A failure of this read leaves `account` empty and does not fail the sign-in |
| `links.manage` | an https URL the connection carries as `links.manage`, for a client to show as a link that changes what the other service grants: for GitHub, installing the App on an account or choosing its repositories. Pons never fetches it |

The connection object of [[002-objects]] gains `links`, copied from its
connector when read, and the OpenAPI document of [[003-api]] gains it.

### GitHub's habits

These are written into the sign-in's handling of a token endpoint for
every connector, not into a GitHub branch, since each is allowed by the
OAuth specifications or harmless to accept:

1. **The token endpoint answers form encoding unless asked.** Every
   token request Pons sends carries `Accept: application/json`.
2. **An error comes back with status `200`.** A token response whose
   JSON has an `error` member is an error, whatever its status.
   `bad_refresh_token` is read as `invalid_grant`, and
   `bad_verification_code` as an exchange that failed.
3. **A refresh token lasts about six months, and rotates.** The answer
   names `refresh_token_expires_in`, which Pons keeps as the
   connection's `expires_at`, and every refresh returns a new refresh
   token, which the one writer of [[007-sign-in]] already handles. This
   needs the App's setting that makes user tokens expire, without which
   GitHub issues a token that never expires and no refresh token, which
   Pons also accepts.

### What a person sees

1. They choose GitHub in a client and are sent to GitHub, where they
   authorize the App.
2. They come back, the client confirms, and the connection shows their
   GitHub login as its `account`.
3. A call that reaches a repository the App is not installed on answers
   as GitHub answers, with no access. The client shows the connection's
   `links.manage` beside it: "Choose repositories on GitHub".

A person who installs the App from GitHub's own pages, before or after
connecting, needs nothing more: the token reaches whatever the App is
installed on at the moment of each call.

### The App's settings

What the operator sets on the GitHub App, in GitHub's settings, which
Pons cannot set for them:

| Setting | Value |
|---|---|
| Callback URL | Pons's callback, `{PONS_PUBLIC_URL}{base}/callback`, beside any callback the App already has |
| Expire user authorization tokens | on |
| Request user authorization during installation | off: the sign-in starts at Pons, which holds the `state` |
| Permissions | what the connector should allow; GitHub's server offers only the tools the token's permissions reach |

The App's client id and secret go into the catalog entry and the
installation's secret store. The App's private key is not needed: Pons
never acts as the App itself.

### If GitHub's server refuses the token

If GitHub's remote MCP server refuses a GitHub App's user token, the
entry's `url` changes to an instance of GitHub's open source MCP server
run beside Pons in its HTTP mode, which takes the caller's token per
request and calls GitHub's API with it. Nothing in Pons changes: the
entry's `url` and `hosts` name that instance instead. Running it is the
installation's, and it is not built unless the check below fails.

## Not in this spec

Reading a person's installations and their repositories as part of the
connection; a connection an organization owns through its own
installation; acting as the App with its private key; an event GitHub
sends when an installation is removed. Each waits for a need.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The entry above validates, `auth.account` and `links.manage` are refused when not https, and `auth.account.url` is refused when its host misses `hosts` | `catalog.TestTheGitHubEntry`, `catalog.TestAccountAndLinksRules` |
| A sign-in against the stub authorization server in GitHub's manner, form encoding unless asked, errors with status `200`, a rotating refresh token, connects, and the connection's `account` is the stub API's `login` | `signin.TestGitHubManner` |
| A failed read of the account leaves `account` empty and the connection connected | `signin.TestAccountReadIsBestEffort` |
| The connection carries `links.manage` from its connector, and a disconnect deletes the credential with no revocation request | `TestLinksAndNoRevokeURL` |
| Against the real GitHub with the installation's App: a person signs in, `tools/list` at the connection's address answers GitHub's tools, and a read tool returns a repository the App is installed on | a manual check before the entry ships, recorded in this spec's Outcome |
