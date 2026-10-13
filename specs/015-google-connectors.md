---
title: "Google's connectors: Gmail, Google Calendar and Google Drive, each signed in with Google on its own and carried as Google's REST APIs"
status: in-progress
track: core
depends_on:
  - specs/006-catalog.md
  - specs/007-sign-in.md
  - specs/.archive/013-github-connector.md
  - specs/.archive/014-http-forwarding.md
affects: [catalog/, internal/signin/]
effort: small
created: 2026-10-13
updated: 2026-10-13
author: changkun
---

# Google's connectors

## Overview

A person connects their mail, their calendar and their files at Google,
and an agent reads them, finds free time, and prepares work for the
person: a draft to send, an event, a file. Three entries give it, one
per product, so a person who wants an agent in their calendar does not
also hand it their mail. Each is an ordinary `oauth` connector with
`discovery: none` ([[007-sign-in]]) of kind `http` ([[014-http-forwarding]]):
the caller uses Google's own REST paths on the connection's forwarding
address, and Pons adds the person's token on the way out.

The three share the one client the operator registers with Google. Each
sign-in asks only for its own product's scopes, so each connection's
token reaches only its own API.

## Current state

The entries load and their sign-in is built from members the catalog
already has; see Implementation status. Nothing of Google's needs code
of its own: GitHub's connector ([[013-github-connector]]) added the
`account` member and the token endpoint habits, and Google's two
requirements of the authorization request are written as a query of
`authorize_url`, which the sign-in already keeps.

Google also runs Model Context Protocol servers for these products. They
are in a developer preview whose terms keep them out of public
applications until they are generally available, so they are not this
connector's path. An operator may add them later as entries of kind
`mcp`.

## Design

### The entries

```yaml
connectors:
  - name: gmail
    title: Gmail
    description: Read and search your mail, and write drafts for you to send.
    icon: https://www.gstatic.com/images/branding/product/2x/gmail_2020q4_48dp.png
    kind: http
    url: https://gmail.googleapis.com
    hosts: ["gmail.googleapis.com", "openidconnect.googleapis.com"]
    auth:
      type: oauth
      discovery: none
      issuer: https://accounts.google.com
      authorize_url: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent+select_account
      token_url: https://oauth2.googleapis.com/token
      client: {id: 123456789012-example.apps.googleusercontent.com, secret: {env: GOOGLE_CLIENT_SECRET}}
      scopes:
        - openid
        - email
        - https://www.googleapis.com/auth/gmail.readonly
        - https://www.googleapis.com/auth/gmail.compose
      resource: false
      account: {url: https://openidconnect.googleapis.com/v1/userinfo, field: email}
  - name: google-calendar
    title: Google Calendar
    description: Read your calendars, find free time, and create and change events.
    icon: https://www.gstatic.com/images/branding/product/2x/calendar_2020q4_48dp.png
    kind: http
    url: https://www.googleapis.com
    hosts: ["www.googleapis.com", "openidconnect.googleapis.com"]
    http:
      read_only: ["POST /calendar/v3/freeBusy"]
    auth:
      type: oauth
      discovery: none
      issuer: https://accounts.google.com
      authorize_url: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent+select_account
      token_url: https://oauth2.googleapis.com/token
      client: {id: 123456789012-example.apps.googleusercontent.com, secret: {env: GOOGLE_CLIENT_SECRET}}
      scopes:
        - openid
        - email
        - https://www.googleapis.com/auth/calendar.calendarlist.readonly
        - https://www.googleapis.com/auth/calendar.events
        - https://www.googleapis.com/auth/calendar.events.freebusy
      resource: false
      account: {url: https://openidconnect.googleapis.com/v1/userinfo, field: email}
  - name: google-drive
    title: Google Drive
    description: Find and read your files, and save new files to your Drive.
    icon: https://www.gstatic.com/images/branding/product/2x/drive_2020q4_48dp.png
    kind: http
    url: https://www.googleapis.com
    hosts: ["www.googleapis.com", "openidconnect.googleapis.com"]
    auth:
      type: oauth
      discovery: none
      issuer: https://accounts.google.com
      authorize_url: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent+select_account
      token_url: https://oauth2.googleapis.com/token
      client: {id: 123456789012-example.apps.googleusercontent.com, secret: {env: GOOGLE_CLIENT_SECRET}}
      scopes:
        - openid
        - email
        - https://www.googleapis.com/auth/drive.readonly
        - https://www.googleapis.com/auth/drive.file
      resource: false
      account: {url: https://openidconnect.googleapis.com/v1/userinfo, field: email}
```

- **`url` is the API's host alone.** A caller writes Google's
  documented path after the forwarding address, such as
  `/gmail/v1/users/me/messages`, `/calendar/v3/calendars/primary/events`
  or `/drive/v3/files`, and the upload paths beside them,
  `/upload/gmail/v1/...` and `/upload/drive/v3/...`, are reached the
  same way. Calendar and Drive share `www.googleapis.com`; a
  connection's token holds only its own product's scopes, so Google
  refuses it at the other's API, and an authorizer may hold `Tools` to a
  product's paths.
- **`discovery: none`.** Google publishes OpenID Connect metadata, but
  the two members below go on the authorization request, and only an
  entry that gives its endpoints gives `authorize_url`. The `issuer` is
  the one Google's metadata states, and Google sends `iss` in its answer
  (`authorization_response_iss_parameter_supported`), which is compared
  with it ([[007-sign-in]]).
- **`access_type=offline` and `prompt=consent select_account`.** Google
  issues a refresh token only to a request with `access_type=offline`,
  and only at the first consent unless the request asks for consent
  again, so a person who reconnects would otherwise get an access token
  that ends in an hour. `select_account` lets a person signed in to
  several Google accounts choose the one to connect. Both are a query of
  `authorize_url`, whose members the sign-in keeps beside its own. A
  query that names one of the sign-in's own, `response_type`,
  `client_id`, `redirect_uri`, `code_challenge`,
  `code_challenge_method`, `state`, `resource` or `scope`, is refused
  when the catalog loads ([[006-catalog]]).
- **Scopes.** `openid email` let the account be read; the rest are the
  product's. `gmail.compose` lets the token create, change and delete
  drafts and also send mail: Google has no scope for drafts alone, so
  keeping an agent from sending is the authorizer's (below).
  `drive.file` reaches only files the connection created or the person
  opened with it.
- **The account** is the `email` of Google's userinfo, read once after
  the sign-in as for GitHub ([[013-github-connector]]); its host is in
  `hosts`, so the token goes nowhere a call would not take it.
- **Refresh.** Google's access token lasts an hour, and its answer to a
  refresh carries no new refresh token, so the one held is kept
  ([[007-sign-in]]).
- **No revocation, for now.** Google's revocation endpoint,
  `https://oauth2.googleapis.com/revoke`, takes a token in the form of
  RFC 7009. Google's documentation does not say whether revoking one
  token ends only that token or the person's whole grant to the client,
  which the three connections share: the second would end a person's
  Calendar when they disconnect Gmail. Until a check against the real
  Google settles it, the entries give no `revoke_url`, and a disconnect
  deletes the credential without revoking it at Google. The person can
  remove the installation's access in their Google Account. If the
  check shows a revocation ends one token alone, the entries add the
  endpoint and nothing else changes.
- **Effects.** `GET` reads and every other method writes
  ([[014-http-forwarding]]), except Calendar's `POST
  /calendar/v3/freeBusy`, a query for free time, which the entry marks
  as reading.

### What an authorizer is expected to hold

Pons carries what the allow admits. An installation that lets an agent
prepare work for a person, and leaves sending and sharing to the person,
answers a `connection.use` of these connections like this:

| Connector | Writes admitted | Refused |
|---|---|---|
| `gmail` | drafts: create, change, delete, under `/gmail/v1/users/*/drafts` and `/upload/gmail/v1/users/*/drafts` | `.../messages/send`, `.../drafts/send`, and every other write |
| `google-calendar` | events: create, change, delete, under `/calendar/v3/calendars/*/events` | every other write, calendars and their sharing included |
| `google-drive` | files: create and change, under `/drive/v3/files` and `/upload/drive/v3/files` | a file's permissions, which share it, a delete, and every other write |

Reads are admitted under the product's own paths. The rules are the
authorizer's, not the catalog's: another installation may draw them
elsewhere.

### The client's settings

What the operator sets in the Google Cloud project, which Pons cannot
set:

| Setting | Value |
|---|---|
| APIs | the Gmail API, the Google Calendar API and the Google Drive API, enabled |
| OAuth consent screen | the installation's name, support email, home page, privacy policy and terms; the domain of Pons's callback as an authorized domain |
| Audience | Internal while only the operator's own organization connects; External for anyone else, in production status, with the limits below until Google verifies the client |
| Data access | the scopes of the three entries |
| Client | type Web application, with Pons's callback, `{PONS_PUBLIC_URL}{base}/callback`, as its one authorized redirect URI |

The client's id goes into the three entries and its secret into the
installation's secret store, named by `client.secret`.

An External client in Google's testing status takes only the test users
it lists, and their refresh tokens end after seven days. In production
status, before Google has verified it, it takes any Google account,
which sees Google's warning that the app is unverified, and at most 100
users with these scopes. Verification lifts both: Calendar's scopes are
sensitive and need Google's review alone; Gmail's and `drive.readonly`
are restricted and need a security assessment beside it, renewed every
year.

## Implementation status

Built: the three entries load as this spec writes them, a sign-in whose
`authorize_url` carries a query sends its members beside the sign-in's
own, and a query that names one of the sign-in's own is refused. The
check against the real Google is open.

| Criterion | State |
|---|---|
| `catalog.TestTheGoogleEntries` | written; loads the entries from this file |
| `signin.TestTheAuthorizeURLsQueryIsKept` | written |
| `catalog.TestLoadRefusals`, its case of a sign-in member in `authorize_url` | written |
| the manual check against the real Google | open |

## Not in this spec

Google's Model Context Protocol servers, above; a connection an
organization makes for its members with domain-wide delegation; Docs,
Sheets and Slides as their own entries, whose files Drive already reads
and exports; push notifications Google sends when mail or an event
changes. Each waits for a need.

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| The entries above validate, of kind `http` with no `resource` member, each account host under its `hosts`, no `revoke_url`, and Calendar's free time query reading while a draft writes | `catalog.TestTheGoogleEntries` |
| The authorization request of an entry whose `authorize_url` carries `access_type` and `prompt` carries both as written beside the sign-in's own members, each of which `catalog.AuthorizationMembers` names, and the sign-in connects | `signin.TestTheAuthorizeURLsQueryIsKept` |
| An `authorize_url` whose query names a member the sign-in sets is refused when the catalog loads | `catalog.TestLoadRefusals` |
| Against the real Google with the installation's client, a person connects each entry and sees their email as its `account`; lists their mail, reads their calendar, asks for free time and lists their files through the forwarding addresses; writes a draft and is refused a send by the installation's authorizer; and, after disconnecting one entry, the other two still answer | a manual check before the entries ship, recorded in this spec's Outcome |
