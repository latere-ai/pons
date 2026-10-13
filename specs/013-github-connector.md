---
title: "A code host's connector: GitHub through a GitHub App, signed in like any connector, with git and the REST API carried through Pons"
status: testing
track: core
depends_on:
  - specs/006-catalog.md
  - specs/007-sign-in.md
  - specs/014-http-forwarding.md
affects: [catalog/, internal/signin/, internal/httpapi/]
effort: medium
created: 2026-10-12
updated: 2026-10-13
author: changkun
---

# A code host's connector

## Overview

GitHub is the first connector an installation is expected to offer. A
person authorizes the installation's GitHub App once, chooses the
repositories it may reach on GitHub, and from then on an agent clones,
pushes and calls GitHub's API through Pons, which adds the person's
token on the way out. This is how hosted assistants connect GitHub
today: their own GitHub App, and git and the API driven by the
product, not a separate tool server.

The entry needs almost nothing of its own. A GitHub App's user sign-in
is an OAuth authorization code flow with a client the operator
registered, so it is an ordinary `oauth` connector with `discovery:
none` ([[007-sign-in]]). It is of kind `http`, so its connections have
a forwarding address for the REST API and a git address for clones and
pushes ([[014-http-forwarding]]). Two catalog members exist for it: the
account a connection acts as is read once after the sign-in, since
GitHub issues no identity token, and a link lets a person choose the
repositories the App reaches.

## Current state

The entry loads and connects against the stubs; see Implementation
status. The precedent is a connector an identity provider
carried for the same GitHub App: it sent the person to GitHub's
authorize endpoint with the App's client id, exchanged the code, kept
the person's token with a sealed refresh token, and read the person's
installations with it. Its flow worked in production with the App an
installation can reuse, until that provider removed it. Its code is not
carried over, since the token
custody it built by hand is what the store does for every connector
([[005-store-and-sealing]]). Three of GitHub's habits it handled are
written down below.

GitHub also runs a Model Context Protocol server. It is not this
connector's path: whether it accepts a GitHub App's user token is not
documented, and an agent with a sandbox does more with git and the API
than with that server's tools. An operator may add it later as a second
entry of kind `mcp`.

## Design

### The entry

```yaml
connectors:
  - name: github
    title: GitHub
    description: Clone, change and push the repositories you choose, and work with their issues and pull requests.
    icon: https://github.githubassets.com/favicons/favicon.png
    kind: http
    url: https://api.github.com
    git:
      url: https://github.com
      inject: {scheme: basic, username: x-access-token}
    hosts: ["api.github.com", "github.com"]
    http:
      pass: ["X-GitHub-Api-Version"]
      pass_back: ["X-RateLimit-*", "X-GitHub-Request-Id", "X-Accepted-GitHub-Permissions"]
    auth:
      type: oauth
      discovery: none
      issuer: https://github.com/login/oauth
      authorize_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
      client: {id: Iv23exampleclientid, secret: {env: GITHUB_APP_CLIENT_SECRET}}
      resource: false
      account: {url: https://api.github.com/user, field: login}
    links:
      manage: https://github.com/apps/{app slug}/installations/new
```

- **`discovery: none`.** GitHub publishes no authorization server
  metadata for a GitHub App's client, so the entry gives the two
  endpoints, and names the issuer GitHub's OpenID configuration at
  `https://github.com/login/oauth/.well-known/openid-configuration`
  states. An `iss` in GitHub's answer is compared with it, and an answer
  without one is accepted because the catalog names this server by its
  endpoints, under the rule of [[007-sign-in]]. Without `issuer`, an
  answer carrying `iss` is refused: the first sign-in against the real
  GitHub, on 2026-10-13, failed that way.
- **No revocation.** GitHub's way to revoke a user's token needs the
  App's client secret as Basic credentials on its API, not the form of
  RFC 7009, so the entry gives no `revoke_url`. A disconnect deletes
  the credential and does not revoke it at GitHub. The person can
  revoke the App's access in their GitHub settings, and the
  connection's page says so.
- **`resource: false`** and **no scopes.** GitHub's token endpoint
  ignores the member, and a GitHub App's token carries no scopes: what
  it may do is the App's permissions, crossed with what the person may
  do, on the repositories the App is installed on.
- **git with `x-access-token`.** GitHub's git host takes a token as the
  password of Basic credentials with that username.
- **The API.** `GET` reads; every other method writes, GraphQL's `POST
  /graphql` included, since a query and a mutation share it
  ([[014-http-forwarding]]).

### Two catalog members

Both are optional on any `oauth` entry, and validated with the rest of
the catalog ([[006-catalog]]).

| Member | Meaning |
|---|---|
| `auth.account` | `{url, field}`. After the code exchange and before the confirm, Pons sends one `GET` to `url` with the new access token, through the dialer, and keeps the string at the top-level JSON member `field` as the connection's `account`. `url` must be https and its host must match `hosts`, so the token goes nowhere a call would not take it. A failure of this read leaves `account` empty and does not fail the sign-in |
| `links.manage` | an https URL the connection carries as `links.manage`, for a client to show as a link that changes what the other service grants: for GitHub, installing the App on an account or choosing its repositories. Pons never fetches it |

### GitHub's habits

These are written into the sign-in's handling of a token endpoint for
every connector, not into a GitHub branch, since each is allowed by the
OAuth specifications or harmless to accept ([[007-sign-in]]):

1. **The token endpoint answers form encoding unless asked.** Every
   token request carries `Accept: application/json`.
2. **An error comes back with status `200`.** A token response whose
   JSON has an `error` member is an error, whatever its status.
   `bad_refresh_token` is read as `invalid_grant`, and
   `bad_verification_code` as an exchange that failed.
3. **An access token lasts 8 hours, a refresh token about six months,
   and every refresh rotates it.** The answer names
   `refresh_token_expires_in`, kept as the connection's `expires_at`,
   and the one writer of [[007-sign-in]] handles the rotation. Without
   the App's token expiry setting, GitHub issues a token that never
   expires and no refresh token, which Pons also accepts.

### Pushes go to the session's own branches

An agent pushes; a person lands. The installation's authorizer answers
a push with `Refs`, the refs this caller may update
([[014-http-forwarding]]), and a hosted agent's session gets the
branches named for the session, such as `refs/heads/agents/*`. A push
to the default branch, or to any other, is refused by Pons before the
pack leaves, whatever the token itself could do at GitHub.

### What a person sees

1. They choose GitHub in a client and are sent to GitHub, where they
   authorize the App.
2. They come back, the client confirms, and the connection shows their
   GitHub login as its `account`.
3. A clone or a call that reaches a repository the App is not installed
   on answers as GitHub answers, with no access. The client shows the
   connection's `links.manage` beside it: "Choose repositories on
   GitHub".

A person who installs the App from GitHub's own pages, before or after
connecting, needs nothing more: the token reaches whatever the App is
installed on at the moment of each request.

### The App's settings

What the operator sets on the GitHub App, which Pons cannot set:

| Setting | Value |
|---|---|
| Callback URL | Pons's callback, `{PONS_PUBLIC_URL}{base}/callback`, exactly, with wildcard matching off |
| User-to-server token expiration | on |
| Request user authorization during installation | off: the sign-in starts at Pons, which holds the `state` |
| Device flow | off |
| Permissions | what the connector should allow: for an agent that works in repositories, contents, issues, pull requests and metadata, read and write |

The App's client id and secret go into the catalog entry and the
installation's secret store. The App's private key is not needed: Pons
never acts as the App itself.

## Implementation status

Built: the entry loads as this spec writes it; a sign-in in GitHub's
manner connects with the account read once, the connection carries
`links.manage`, and a disconnect revokes nothing; git and the REST API are
carried through the git and forwarding addresses of
[[014-http-forwarding]], a push held to the refs of its allow. The e2e
tier runs the whole path against the stubs: a sign-in, a clone, a push of
a session's branch, a push to `main` refused, the issues listed through
the forwarding address with the next page's `Link` under it, and, once the
person takes the App's access away at GitHub, a `409
connection_not_connected` on the next request.

The manual check against the real GitHub passed on 2026-10-13; the
Outcome records it.

| Criterion | State |
|---|---|
| `catalog.TestTheGitHubEntry`, `catalog.TestAccountAndLinksRules` | written; the first loads the entry from this file |
| `signin.TestGitHubManner` | written |
| `signin.TestAccountReadIsBestEffort` | written |
| `TestLinksAndNoRevokeURL` | written, in the e2e tier |
| the manual check against the real GitHub | passed on 2026-10-13 |

## Outcome

Checked against the real GitHub on 2026-10-13, with an installation's
GitHub App and a person's own account, through the chat of that
installation:

- **Sign-in.** The first attempt was refused at the callback: GitHub
  sends `iss` in its answer, and the entry named no `issuer`, so the rule
  of [[007-sign-in]] refused it. The entry now names
  `https://github.com/login/oauth`, the issuer GitHub's OpenID
  configuration states. The next attempt connected, and the connection
  showed the person's login as its `account`.
- **Clone.** The session's sandbox cloned the person's repository
  through the git address; three `git-upload-pack` requests, each
  answered 200 by GitHub. The first try was refused by the installation's
  authorizer, which read no connection kind: the shared authorizer
  envelope keeps `kind` for the resource itself and drops a field of
  that name. That was fixed in the authorizer. The field's name is a
  defect of [[004-identity-and-authorization]] to rename.
- **Push.** A push to a branch under `refs/heads/agents/` landed on
  GitHub with the agent as its author; a push to another branch and one
  to `main` were refused before any of the pack left, as the allow's
  `Refs` says. git showed only `HTTP 403`: the reason
  [[014-http-forwarding]] promises a person sees is not yet written in
  git's protocol.
- **The REST API.** `GET /repos/{owner}/{repo}/issues` through the
  forwarding address was answered by GitHub.

## Not in this spec

Reading a person's installations and their repositories as part of the
connection; a connection an organization owns through its own
installation; acting as the App with its private key; an event GitHub
sends when an installation is removed; archive downloads, which GitHub
redirects to another host ([[014-http-forwarding]]). Each waits for a
need.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The entry above validates, `auth.account` and `links.manage` are refused when not https, and `auth.account.url` is refused when its host misses `hosts` | `catalog.TestTheGitHubEntry`, `catalog.TestAccountAndLinksRules` |
| A sign-in against the stub authorization server in GitHub's manner, form encoding unless asked, errors with status `200`, a rotating refresh token, connects, and the connection's `account` is the stub API's `login` | `signin.TestGitHubManner` |
| A failed read of the account leaves `account` empty and the connection connected | `signin.TestAccountReadIsBestEffort` |
| The connection carries `links.manage` from its connector, and a disconnect deletes the credential with no revocation request | `TestLinksAndNoRevokeURL` |
| Against the real GitHub with the installation's App, a person signs in, clones a repository the App is installed on through the git address, pushes a branch under `refs/heads/agents/` and is refused a push to the default branch, and lists the repository's issues through the forwarding address | a manual check before the entry ships, recorded in this spec's Outcome |
