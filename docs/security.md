# Security

For an operator deciding how to run Pons and a builder deciding what to
send it: what Pons guarantees, what it sees and keeps, what it does not
defend, and what an operator keeps safe. Reporting a vulnerability, and
the test that holds each guarantee, are in [SECURITY.md](../SECURITY.md).

## What Pons guarantees

**A credential is accepted once and never returned.** A key, a client
secret, an access token and a refresh token reach Pons once and leave it
only toward the service they belong to. No route, list, error, log line
or call record carries one, and the caller of a connection never holds
it.

**A credential goes only where its connector says.** It is placed on a
request to a host the catalog entry lists, in the header the entry
names, and nowhere else. A refresh token or a client secret goes only to
the token endpoint recorded with it.

**A credential at rest is sealed.** Each one is encrypted under a key of
its own, which is wrapped by a sealing key the database never holds.
Each is bound to its row: copied to another connection, or with the
address it is sent to rewritten, it no longer opens. A reader of the
database without the sealing keys learns nothing of any credential.

**Every request to the API is verified and asked about.** Each one
carries a token from an issuer the operator listed, and nothing acts
before the authorizer, or the owner policy, has decided. The routes
that take no token are the sign-in callback, the client documents Pons
names itself with, the OpenAPI document, `version` and the probes. A
connection somebody else owns answers exactly as one that does not
exist.

**No decision is a refusal.** An authorizer that does not answer, or
answers something Pons cannot read, refuses the request, and nothing is
done.

**The caller's own token stays with Pons.** It is removed before a
request leaves for the service, with every header Pons does not pass.
The service's own sign-in challenge, its cookies and its redirects never
reach the caller, so a client is never sent to sign in at the service
around Pons.

**A tool call is held to what the allow names.** On an MCP address,
Pons reads the tool a call names and refuses one outside the allow's
`tools`, a tool the catalog does not mark as only reading under a
read-only allow, and a tool the catalog hides, before the credential is
opened.

**Pons reaches public addresses only.** Toward a service and its
sign-in, Pons connects over `https` to names that resolve to public
addresses alone, so an address a person adds, or one a service's
document names, cannot aim Pons at the installation's own network.

**A request stays on its connector.** A forwarded path cannot climb out
of the service's address, and a redirect anywhere else is not followed.

**A push goes where it is allowed.** Under an allow that names the
branches a push may update, a push to any other is refused before any of
it reaches the service.

**A record says a call happened, not what it said.** A call record holds
who called, when, the method, the tool, the path or the git service, and
the outcome, never an argument, a result, a header or a query string.

## What Pons sees

| What | Where it goes |
|---|---|
| A person's keys, client secrets, access tokens and refresh tokens | sealed in the database, or in the process's memory with no `PONS_DATABASE_URL` |
| Each connection: its owner, name, connector, state, the scopes granted, the account the service reports, and when it was last used, to the minute | the database, in the clear |
| A connector someone added by its address: its address, hosts, way to sign in and tool marks | the database, in the clear; a client secret given for it is sealed |
| Each call through an address: who called, the session their token names, when, the method, the tool or the path, read or write, how many refs a push named, the outcome, the status, and the size of each body | a call record ([API](api.md#call-records)) |
| Each action a caller takes | the authorizer, as the question in [Writing an authorizer](authorizer.md#the-question): the caller's subject and every claim of its token, the action, the object, and the request's id, peer address and user agent; never an argument, a result or a credential |
| One line per call: its id, connection, connector, outcome, status, duration and the size of each body | the log on standard error, and over OTLP with `OTEL_EXPORTER_OTLP_ENDPOINT` set ([Configuration](configuration.md)) |

## How long it keeps things

- **A call record** is kept for `PONS_RECORDS_RETENTION`, 30 days by
  default, and every replica removes older ones every ten minutes. A
  record stays after its connection is disconnected, until its retention
  passes.
- **An idempotency key** is kept for 24 hours, with the route, the
  status and the object the request made, and no body.
- **A sign-in in progress** waits 10 minutes for the person's browser
  to come back and then 2 minutes for your app's confirm. Each replica
  removes the ones that ran out every minute.
- **A disconnect** removes the connection, its sealed credential and any
  sign-in in progress, in one transaction. Then, once and best effort,
  Pons revokes the grant at the revocation endpoint recorded with the
  credential, unless another connection holds the same grant. A pasted
  key cannot be revoked this way: remove it at the service.
- **With no `PONS_DATABASE_URL`**, everything is held in the process and
  is gone when it exits.

## For a builder

- A connection shows its state, its scopes and the account it reaches,
  never its key or its tokens. A connector read through the API shows of
  its way to sign in only the type, the scopes, where the credential
  goes and the hint.
- A connection or a connector the caller may not reach answers `404`,
  exactly as one that does not exist. Two reasons your authorizer may
  send break that on purpose, `kept_apart_from_google` and
  `name_unusable`; send them only as [Denies](authorizer.md#denies)
  says, since each answer says the id exists.
- The path of a forwarded call is kept in its record. Put no secret in a
  path; the query string and the headers are not kept.
- A denied call is recorded at most once a minute per caller and
  connection on each replica, so the records show that a caller was
  refused, not how often.

## What Pons does not defend

[SECURITY.md](../SECURITY.md#what-is-not-defended) is the full list.
The limits an operator plans around:

- **Whoever holds the sealing keys.** The operator of an installation
  can open every credential in it.
- **A service that misuses the access a person granted it.** Pons
  carries calls to the service the person chose.
- **An authorizer that answers wrongly,** or an issuer that signs a token
  for the wrong subject. Pons follows the decision it is given.
- **A compromised host.** The process's memory holds the sealing keys and
  the tokens it has opened.
- **What a model does with an answer it read.** Pons bounds what a
  tricked agent can do through Pons, not what it does elsewhere.
- **A caller's token taken from the caller,** or a sign-in's one-time
  code given away. Pons cannot tell the holder from the owner.
- **A catalog written wrongly,** such as hosts wider than the service's
  own, or a tool that changes something marked as one that only reads.
- **Load beyond the limits you configure.** The limits on requests in
  flight and on creates hold on each replica, so three replicas admit
  three times as many.

## For an operator

| Secret | What its holder can do |
|---|---|
| `PONS_SEALING_KEYS` | open every credential the database holds |
| `PONS_DATABASE_URL`, `PONS_DATABASE_POOL_URL` | read and change every connection and call record, and remove credentials; not open them without the sealing keys |
| the file of `PONS_AUTHORIZER_TOKEN_FILE` | call your authorizer as `ponsd` |
| the variables and files a catalog's secret references name | sign in to the services of those entries as your installation's application |
| a user and a password in `PONS_OUTBOUND_PROXY` | use the proxy every request to another service goes through |

Beside the secrets:

- Keep the sealing keys where your other secrets live, never beside the
  database, and rotate them as [Install](install.md#sealing-keys) says.
- Never set `PONS_DIAL_ALLOW_PRIVATE` outside a test. It removes the rule
  that keeps a connector from reaching your network.
- Run the image with a read-only root file system and every capability
  dropped, and give its network rule port 443 to the internet without
  the private ranges ([Install](install.md#the-network)).
- An authorizer must deny the reserved probe; `ponsd check` asks it, and
  `ponsd` refuses to start against one that allows it
  ([Writing an authorizer](authorizer.md#failing-closed)).
- `PONS_OIDC_ISSUERS` accepts `http` issuers. List only `https` ones
  outside a test, since a token is trusted as far as the keys it is
  checked against.
- With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the logs, traces and metrics
  leave the host for that endpoint.
- List in `PONS_RETURN_URLS` only the addresses of your own app.
