# The catalog

The catalog is the list of services an installation offers, written by
its operator as one YAML file and named by `PONS_CATALOG_FILE`. Each
entry is a connector: what the service is, where Pons reaches it, the
hosts its credential may be sent to, and how a person gives access. A
person connects an entry, and the connection is theirs.

```yaml
connectors:
  - name: forge
    title: Example Forge
    kind: http
    url: https://api.forge.example.com
    git: {url: https://forge.example.com}
    hosts: ["api.forge.example.com", "forge.example.com"]
    auth: {type: token}
```

## Validation

`ponsd` reads the file once at start and validates all of it before it
serves. Any problem stops the start, with one line per problem naming
the entry and the member:

```text
catalog: connectors[0] "tracker": auth.client.secret: the reference does not resolve: the variable TRACKER_CLIENT_SECRET is not set
```

A key the format does not describe is refused at every level, and so is
a member of another way to give access, so a mistake is never silently
ignored. `ponsd check` runs the same validation and serves nothing.
Nothing reloads the file: changing the catalog is a restart, so every
replica of one rollout serves the same connectors, and an existing
connection keeps some of what its entry said when it was made
([below](#a-connector-that-changes-or-is-removed)). Without
`PONS_CATALOG_FILE` the catalog is empty, and the server says so at
start.

## Members

| Member | Required | Rule |
|---|---|---|
| `name` | yes | the entry's name, which a connect names: lowercase letters, digits and hyphens, not starting or ending with a hyphen, at most 40 characters, unique in the file |
| `title` | yes | what a person reads, at most 60 characters |
| `description` | no | at most 200 characters |
| `icon` | no | an `https` URL. Pons never fetches it |
| `kind` | yes | `http` or `mcp`, below |
| `url` | yes | where the service is: an `https` URL with no user part and no fragment |
| `hosts` | no | the hosts a credential of this connector may be sent to. The host of `url` when absent |
| `auth` | yes | `type`, and the members of that way to give access |
| `git` | no | kind `http` alone: the service's git host |
| `http` | no | kind `http` alone: which requests only read, and which headers pass |
| `tools` | no | `read_only` and `hidden`, globs over tool names, for kind `mcp` |
| `links.manage` | no | an `https` URL a client may show beside a connection, where a person changes what the service grants. Pons never fetches it |

Every address an entry names, `url`, `git.url` and the endpoints under
`auth`, is `https`, and its host is a name: an IP address, a single
label such as `intranet`, `localhost`, and any name under `localhost`,
`local`, `internal` or `home.arpa` are refused. A port other than 443
is allowed, and becomes a port Pons may connect to for this connector.

## Kinds

**`http`** is any HTTP API. A connection of kind `http` has a
forwarding address that carries plain HTTP to `url`, and, when the
entry names `git.url`, a git address that carries git's smart HTTP
protocol to that git host ([API](api.md#the-addresses)).

| Member | Meaning |
|---|---|
| `git.url` | the git host's base, such as `https://forge.example.com` |
| `git.inject` | where the credential goes on a git request: `{scheme: bearer}` sends `Authorization: Bearer`, the default for `oauth` and `client_credentials`; for `token` without `git.inject` the key goes where `inject` says. `{scheme: basic, username: <name>}` sends `Authorization: Basic` of the username and the credential |
| `http.read_only` | requests that only read beyond `GET`, `HEAD` and `OPTIONS`, as a method in capitals, one space and a glob over the path below the address: `POST /search/*` |
| `http.pass` | request headers passed to the service on the forwarding address beside the ones Pons always passes, such as an API version header. Not the credential's header, and not one Pons sets or removes itself. The git address passes its own fixed set and ignores this list |
| `http.pass_back` | globs of response headers passed back to the caller, matched without regard to case, such as `X-RateLimit-*`. No glob passes `Set-Cookie`, `WWW-Authenticate` or a hop-by-hop header such as `Connection`, and `Link` and `Location` come back only as Pons rewrites them ([API](api.md#the-addresses)) |

The effect of a request, `read` or `write`, is what an authorizer is
asked about and what a call record keeps. `GET`, `HEAD`, `OPTIONS` and
an `http.read_only` match read, and every other request writes. On the
git address, a clone or a fetch reads and a push writes.

**`mcp`** is a Model Context Protocol server, and `url` its address.
**This release does not serve the address a caller would use for it.**
A catalog entry of kind `mcp` loads, can be listed and connected, and
its connections cannot be called yet. `tools.read_only` marks the tools
that only read, and `tools.hidden` the tools a client should not offer;
a tool no `read_only` glob matches is treated as one that changes
something. In a glob, `*` stands for any run of characters, and a glob
matches a whole name, by case.

## Ways to give access

`auth.type` is how a person gives access. Each takes its own members and
refuses another's.

### A pasted key

`type: token`. A person pastes a key when they connect, and it belongs
to their connection, never to the catalog.

| Member | Default | Meaning |
|---|---|---|
| `inject.header` | `Authorization` | the request header the key is placed in |
| `inject.format` | `Bearer {value}` | the header's value, with `{value}` exactly once, in visible ASCII and spaces |
| `hint` | | one sentence, at most 200 characters, telling a person where to get the key |

For kind `http` the key is tried once before it is kept, by a `GET` of
`url` with the key in its place. A `401` or a `403` refuses it, and any
other answer accepts it, since many an API answers its root with a
`404`. On the git address the key goes where `git.inject` says when the
entry gives one, and where `inject` says otherwise.

### A sign-in

`type: oauth`. A person signs in at the service, and Pons keeps the
access token and the refresh token it is given and refreshes them.

| Member | Default | Meaning |
|---|---|---|
| `discovery` | `resource` for kind `mcp`; required for `http` | how Pons finds the service's authorization server. `resource`: the service publishes protected resource metadata (RFC 9728). `issuer`: `issuer` names an authorization server that publishes its metadata (RFC 8414 or OpenID Connect discovery). `none`: the entry gives the endpoints |
| `issuer` | | the authorization server's issuer, an `https` URL. Required with `discovery: issuer`, and with `resource` when the entry gives a `client`. With `none`, what an `iss` in the service's answer is compared with |
| `authorize_url`, `token_url` | | the endpoints. Required with `discovery: none`, refused otherwise. `authorize_url` may carry a query, for members a server needs on the authorization request, which the sign-in keeps beside its own. A query that names one of the sign-in's own members, `response_type`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`, `resource` or `scope`, is refused when the catalog loads |
| `revoke_url` | | the revocation endpoint (RFC 7009), with `discovery: none` alone; with `resource` or `issuer`, Pons uses the one the server's metadata names. A sign-in records the endpoint, and a disconnect revokes there; without one it deletes the credential and revokes nothing |
| `client.id`, `client.secret` | | the OAuth application you registered at the service. `secret` is a [reference](#secrets), absent for a public client. Required with `discovery: none` |
| `scopes` | | the scopes to ask for. Without it, a `resource` sign-in asks for the scopes the service's challenge or its resource metadata names, and an `issuer` or `none` sign-in names none. With `resource` or `issuer`, Pons adds `offline_access` whenever the authorization server's metadata lists it |
| `resource` | `true` for `mcp`, `false` for `http` | whether the sign-in names the service a token is for (RFC 8707). Turn it off for a server that refuses the member |
| `account` | | `{url, field}`: after the sign-in, Pons sends one `GET` to `url` with the new token and keeps the string at the top-level JSON member `field` as the connection's `account`, such as a login. `url` is `https` and on a host `hosts` covers. A failure leaves `account` empty and does not fail the sign-in |

With `discovery` `resource` or `issuer`, the authorization server's
metadata must name its issuer exactly, both endpoints, and the proof
key method `S256`, which Pons uses on every sign-in. Pons identifies
itself by the entry's `client` when it gives one. Otherwise, it uses its
client metadata document when the server supports that and
`PONS_PUBLIC_URL` is `https`, or registers itself when the server offers
registration. A server that allows none of these cannot be connected:
`422 sign_in_unsupported`.

**The issuer rule.** When the service sends the browser back, its answer
may carry `iss`, the issuer that answered (RFC 9207). Pons compares it,
as a string, with the issuer it recorded when the sign-in started, and
refuses any other. An answer without `iss` is refused when the server's
metadata says it sends one, and is otherwise accepted only from a server
the catalog names: by its endpoints, with `discovery: none`, or by
`issuer`. With `discovery: none`, a service that does send `iss` needs
`issuer` in the entry, or every answer is refused. A refused answer
sends the browser back to your app with `error=sign_in_failed`.

### Client credentials

`type: client_credentials`. The connection holds its owner's own client
id and secret, given when they connect, and Pons mints a token from them
at use and again when it runs out.

| Member | Meaning |
|---|---|
| `token_url` | the token endpoint. Required |
| `scopes` | the scopes to ask for |
| `audience` | the `audience` member some servers want in the request |

The client is tried once, by a first mint, before it is kept.

### No credential

`type: none`, with no other member. The connection records that its
owner turned the connector on, and its requests carry no credential.

## Secrets

A secret is never written in the file. The one secret a catalog names,
an OAuth application's client secret, is a reference with exactly one
member: `{env: NAME}`, the value of a variable of `ponsd`'s environment,
or `{file: /absolute/path}`, the contents of a file, with one trailing
newline removed. Each reference is resolved at start to prove it
resolves, and read again at each use, so a mounted file can be rotated
without a restart. A value written in place of a reference stops the
start.

A key a person pastes and a client a person gives belong to their
connection, arrive through the API, and are sealed there. A connector
read through the API shows of `auth` only `type`, `scopes`, `inject` and
`hint`: no client, no reference and no endpoint.

## Hosts

`hosts` lists the hosts a credential of the connector may be sent to:
exact names of two labels or more, or `*.` before such a name.
`*.example.com` matches every name under `example.com`, at any depth,
and not `example.com` itself. A pattern carries no port. The list must
cover the host of `url`, of `git.url` and of `auth.account.url`.

A name says nothing about the address it resolves to, so Pons checks
again when it connects: a name that resolves to any private, loopback or
link-local address is refused, and a credential is only ever placed on a
request to a host of this list. A refresh token or a client secret goes
only to the token endpoint, and the revocation endpoint, recorded with
it.

## A connector that changes or is removed

A changed entry applies to its existing connections from the restart
on, except what a credential records when it is made. A pasted key
keeps the `inject` it was given under; a client keeps the `token_url`,
`scopes` and `audience`; a sign-in keeps the endpoints, the client and
the scopes it was made with, the revocation endpoint included. Each
keeps them until the person gives a new key or client, or reconnects.
Changing `client.id` breaks the refresh of the connections made with
the old one, while a new `client.secret` under the same id is read at
its next use.

Removing an entry takes nothing with it. Its connections are kept with
their credentials, and a request to one answers
`409 connection_not_connected` with the reason `connector_removed` until
the entry returns. An entry whose `kind` or `auth.type` changed is, for
an existing connection, removed. Never give a removed entry's `name` to
another service: its connections would send their credentials to the
new service's hosts.

## The example file

[`catalog/example.yaml`](../catalog/example.yaml) has one entry per way
to give access, for invented services. All four are of kind `mcp`, so
none can be called in this release. Since the services are invented,
only `search` and `weather` can be connected, and the file loads only
with `TRACKER_CLIENT_SECRET` set:

```yaml
connectors:
  - name: tracker
    title: Example Tracker
    description: Read and file the issues of your projects.
    kind: mcp
    url: https://mcp.tracker.example.com/mcp
    auth:
      type: oauth
      discovery: issuer
      issuer: https://login.example.com
      client: {id: pons, secret: {env: TRACKER_CLIENT_SECRET}}
      scopes: ["issues:read", "issues:write"]
    tools:
      read_only: ["search_*", "get_*", "list_*"]
      hidden: ["delete_project"]
  - name: search
    title: Example Search
    kind: mcp
    url: https://api.search.example.net/mcp
    auth:
      type: token
      inject: {header: X-Api-Key, format: "{value}"}
      hint: Create a key under Settings, API keys, at search.example.net.
    tools: {read_only: ["*"]}
  - name: warehouse
    title: Example Warehouse
    kind: mcp
    url: https://mcp.warehouse.example.org/mcp
    hosts: ["mcp.warehouse.example.org"]
    auth:
      type: client_credentials
      token_url: https://login.warehouse.example.org/oauth/token
      scopes: ["query"]
      audience: https://mcp.warehouse.example.org
  - name: weather
    title: Example Weather
    kind: mcp
    url: https://weather.example.org/mcp
    auth: {type: none}
    tools: {read_only: ["*"]}
```

- **tracker** signs people in at an authorization server the entry
  names by its issuer, as the client `pons` the operator registered
  there. The secret is read from the variable `TRACKER_CLIENT_SECRET`,
  so `ponsd` refuses to start without it.
- **search** takes a pasted key, sent as `X-Api-Key: <key>`.
- **warehouse** holds each person's own client, and mints a token for
  the audience the entry's `audience` names.
- **weather** takes no credential.

## GitHub

GitHub is connected through a GitHub App you create. A person authorizes
the App once and chooses the repositories it may reach on GitHub. From
then on a caller clones, fetches and pushes over the git address, and
calls the REST API over the forwarding address, and Pons adds the
person's token on the way out.

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
      client: {id: <the App's client id>, secret: {env: GITHUB_APP_CLIENT_SECRET}}
      resource: false
      account: {url: https://api.github.com/user, field: login}
    links:
      manage: https://github.com/apps/<the App's name>/installations/new
```

- **`discovery: none`** with the two endpoints, since GitHub publishes no
  authorization server metadata for an App's client. GitHub's answer
  carries `iss`, so the entry names `issuer`, the value GitHub's own
  OpenID configuration states; without it every sign-in is refused at
  the callback.
- **No `revoke_url`.** GitHub revokes an App's user token through its
  REST API, not the form of RFC 7009, so a disconnect deletes the
  credential and does not revoke it at GitHub. A person revokes the
  App's access in their GitHub settings.
- **`resource: false` and no scopes.** A GitHub App's token carries no
  scopes: it may do what the App's permissions allow, crossed with what
  the person may do, on the repositories the App is installed on.
- **git with `x-access-token`.** GitHub's git host takes the token as the
  password of Basic credentials with that username.
- **The API.** `GET`, `HEAD` and `OPTIONS` read, and every other method
  writes, GraphQL's `POST /graphql` included.
- **`account`** reads the person's login once after the sign-in, and
  **`links.manage`** is where they install the App on more repositories.

Pons also accepts GitHub's habits at its token endpoint: a form-encoded
answer unless JSON is asked for, which Pons always asks for; an error
with status `200`; and an access token of eight hours with a refresh
token that rotates on every refresh.

Set the App up this way:

| Setting | Value |
|---|---|
| Callback URL | Pons's callback, `{PONS_PUBLIC_URL}{PONS_BASE_PATH}/callback`, exactly |
| Expire user authorization tokens | on |
| Request user authorization (OAuth) during installation | off: the sign-in starts at Pons, which holds its state |
| Enable Device Flow | off |
| Permissions | what callers should be able to do; for an agent working in repositories, contents, issues, pull requests and metadata, read and write |

The App's client id and a client secret go into the entry and your
secret store. The App's private key is not needed: Pons never acts as
the App itself.

What a push may update is your authorizer's to say. An allow that names
`refs`, such as `["refs/heads/agents/*"]`, holds every push through the
connection to those branches, and a push to any other is refused before
any of it reaches GitHub, whatever the person's token could do there,
with the rule as the reason git prints
([Writing an authorizer](authorizer.md#limits)).
