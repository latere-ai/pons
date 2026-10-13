# Writing an authorizer

Pons verifies who is calling and asks somebody else what they may do.
That somebody is an HTTP endpoint you write, named by
`PONS_AUTHORIZER_URL`: before any route acts, and before any request to
a connection's address leaves, Pons asks it one question and does what
the answer says. An allow may also carry limits that Pons holds the
request to, such as the branches a push may update. With no endpoint
configured, a built-in [owner policy](#the-owner-policy) answers
instead.

This page is the contract. The Go package
[`latere.ai/x/pons/authorizer`](../authorizer) publishes the vocabulary
and the limits as code, so an endpoint written in Go keeps no copy of
the strings.

## The question

Pons sends a `POST` to `PONS_AUTHORIZER_URL` with
`Authorization: Bearer <token>`, where the token is the content of the
file `PONS_AUTHORIZER_TOKEN_FILE` names, and a JSON body. Refuse any
other bearer.

```json
{
  "subject": "https://login.example.com|alice",
  "issuer": "https://login.example.com",
  "sub": "alice",
  "claims": {"iss": "https://login.example.com", "sub": "alice", "aud": "pons", "iat": 1791899940, "exp": 1791903540},
  "action": "connection.use",
  "resource": {
    "kind": "Connection",
    "id": "con_01m4ts0s3y6jb3gj2j8e7pt7sn",
    "owner": "https://login.example.com|alice",
    "connector": "github",
    "name": "github",
    "connection_kind": "http",
    "method": "POST",
    "tool": "git-receive-pack",
    "effect": "write",
    "refs": ["refs/heads/agents/fix-login"]
  },
  "request": {"id": "", "ip": "10.0.4.17", "user_agent": "git/2.47.0"}
}
```

| Member | What it is |
|---|---|
| `subject` | the caller: the token's issuer and `sub` joined by a pipe. It is what an `owner` holds |
| `issuer`, `sub` | the two halves apart |
| `claims` | every claim of the caller's verified token, as the issuer wrote it. Pons reads none of them for meaning: roles, groups, organizations and scopes are yours to read here |
| `action` | one action of the [vocabulary](#the-vocabulary) |
| `resource` | what the action is about: `kind`, `Connector` or `Connection`; `id` for a stored object; and the members the action sends, each present only when Pons knows it |
| `request` | the request's `X-Request-Id`, the peer address as `ponsd` sees it, and the user agent |

## The answer

Answer `200` with a JSON object:

```json
{"allow": true, "reason": "agent session", "ttl": 60, "limits": {"refs": ["refs/heads/agents/*"]}}
```

| Member | What it is |
|---|---|
| `allow` | required: `true` or `false` |
| `reason` | your word for the answer. On a refused create or list it reaches the caller as `details.reason`, never in the sentence a person reads |
| `ttl` | seconds Pons may keep an allow, 60 when absent and 600 at most |
| `limits` | what an allow holds the request to, [below](#limits) |
| `filter` | on a list: `{"owners": [...]}`, the owners whose objects the caller may see |

Pons keeps an allow for its `ttl` and a deny for 5 seconds, keyed by the
whole question, every claim and the peer included, so a change at your
end reaches a caller within the `ttl` you chose. A question about a
resource with no `id`, a create or a list, is never kept and always
asked.

## The vocabulary

| Kind | Action | Asked by | Resource members |
|---|---|---|---|
| `Connector` | `connector.list` | the list of connectors | none |
| `Connector` | `connector.read` | a read of one connector | `name` for a catalog connector; `id` and `owner` for one a person added; `connector_kind` |
| `Connector` | `connector.create` | adding a connector by its address | `owner` when the request names one, `connector_kind`, `host` |
| `Connector` | `connector.delete` | removing an added connector | `id`, `owner` |
| `Connection` | `connection.create` | a connect; and a confirm, a reconnect and a replaced key, which send the stored connection's `id` | `owner` when named or stored, `connector`, `name`, `connection_kind`, `auth`, `id` |
| `Connection` | `connection.read` | a read of a connection, and of its call records | `id`, `owner`, `connector`, `name`, `connection_kind`, `auth` |
| `Connection` | `connection.list` | the list of connections | `owner` when the request names one |
| `Connection` | `connection.update` | a rename | `id`, `owner`, `connector`, `name`, `connection_kind`, `auth` |
| `Connection` | `connection.delete` | a disconnect | `id`, `owner`, `connector`, `name`, `connection_kind`, `auth` |
| `Connection` | `connection.use` | every request to a connection's address | `id`, `owner`, `connector`, `name`, `connection_kind`, `method`, `tool`, `effect`, and `refs` for a push |

- **`kind` and `id`** are the resource's own: `resource.kind` is
  `Connector` or `Connection`, and `resource.id` the id of a stored
  object. The kind of the connector or the connection, `http` or `mcp`,
  is `connector_kind` or `connection_kind`.
- **`connector`** is a catalog name, or the id of a connector a person
  added. **`auth`** is how the connector takes access: `oauth`, `token`,
  `client_credentials` or `none`. **`host`** is the host of the address a
  person asks to add, so you can hold added connectors to the domains you
  choose.
- **`owner` on a create** is the owner the request names, when it names
  one: a service connecting for a person, or a member acting in a team's
  space. You decide whether the caller may. A request that names no owner
  leaves the member out, which means the caller's own. Either way, your
  allow may say whose the new object is, in `limits.owner`.
- **`connection.use`** names what the request does. `method` is the HTTP
  method. On the forwarding address, `tool` is the path below the
  address, such as `/repos/acme/app/issues`; on the git address it is
  `git-upload-pack`, a clone or a fetch, or `git-receive-pack`, a push.
  `effect` is `read` or `write` by the connector's rules
  ([The catalog](catalog.md#kinds)). `refs` are the full names of the
  refs a push updates.
- The callback, the client metadata documents and the OpenAPI document
  ask nothing.

## Limits

An allow may carry limits. Pons enforces what it is told and stores no
plan. Every member is optional, and the object takes these keys and no
others:

| Member | Read from the allow of | Holds |
|---|---|---|
| `owner` | `connection.create` with no `id`, `connector.create` | whose the new object is. Without it, the owner the request named, or the caller |
| `max_connections` | `connection.create` with no `id` | how many connections the owner may hold. It lowers the installation's `PONS_MAX_CONNECTIONS_PER_OWNER` and never raises it. Past it, `403 forbidden` on `owner` |
| `connectors` | `connection.create` with no `id` | globs of the connector references the caller may connect. `ctr_*` admits every added connector, and a list of catalog names admits none. Outside them, `403 forbidden` on `connector` |
| `read_only` | `connection.use` | `true` refuses a request whose effect is `write`: `403 forbidden` on `tool` |
| `tools` | `connection.use` | globs of the `tool` values the caller may use, such as `["/repos/acme/*", "git-upload-pack"]`. Outside them, `403 forbidden` on `tool` |
| `refs` | `connection.use` | globs of the full ref names a push may update, such as `["refs/heads/agents/*"]`. A push naming any other, a deletion included, is refused and none of it reaches the service. It is answered in git's own protocol, so git prints the rule, such as `only branches under refs/heads/agents/ may be pushed by this caller` |
| `requests` | `connection.use` | the requests the caller may send to the forwarding address, each a method in capitals, one space, and a path pattern, such as `["GET /**", "POST /repos/*/*/issues"]`. In a pattern `*` is exactly one non-empty segment, a last `**` is the rest of the path, and `/` alone is the address itself. Outside them, `403 forbidden` on `tool` with the reason `requests`, so the caller learns the request is not allowed rather than that the connection is missing. The git address is held by `refs` instead |
| `calls_per_minute` | `connection.use` | how many requests the caller may send to the connection in a minute, counted per replica. Past it, `429 rate_limited` |

In a glob, `*` stands for any run of characters, the empty one
included, and a glob matches a whole value, by case. An empty list is no
limit. The limits of any other action's allow are not read.

A limit refuses after an allow, so the caller gets a `403` that names
the member (`429` for `calls_per_minute`), not a `404`, and nothing
reaches the service. A push outside
`refs` is the one exception, answered as a git host refuses a push so
that git shows the person why. A limits
object Pons cannot read, with a key it does not know, a figure below
zero or an empty glob, is no answer: the request fails closed.

A typical allow for an agent's session that may read a person's
repositories and push only its own branches:

```json
{"allow": true, "ttl": 300, "limits": {"refs": ["refs/heads/agents/*"], "calls_per_minute": 600}}
```

## Lists

An allow of `connection.list` or `connector.list` names in `filter` the
owners whose objects the caller may see. An allow with no filter lists
the caller's own. The request's `owner` parameter narrows the list
further and never widens it, and a list that names an owner sends it in
the question, so you can answer a service that lists one person's
connections with a filter naming that person. For `connector.list` the
filter narrows the connectors people added; the catalog is listed
whatever it says. A filter that names labels cannot be applied, since
nothing in Pons is labeled, and is no answer.

## Denies

A deny of a create or a list is `403 forbidden` to the caller. A deny
about a stored object, a read, a change, a use, a confirm, is answered
exactly as a missing object, with the `404` of its kind, so a caller
cannot learn that an id exists.

## Failing closed

Anything that is not a well-formed answer is no decision: a status other
than `200`, a body that does not parse or has no `allow`, no answer
within 5 seconds, and limits or a filter that cannot be read. Pons tries
once more when the connection to your endpoint failed, and otherwise
not. A request with no decision does nothing, and the caller gets
`503 authorizer_unavailable`, which names neither your endpoint nor its
bearer.

At start, and in `ponsd check`, Pons sends a probe: the action
`connection.read` with no subject and the reserved resource id
`00000000-0000-0000-0000-000000000001`. Deny it, always, for every
subject and action. An endpoint that allows the probe does not read the
request, and `ponsd` refuses to start against it. An endpoint that does
not answer the probe is named in the log, and the server starts with
every request failing closed until it answers.

## The owner policy

With `PONS_AUTHORIZER_URL` unset, the owner policy answers, and
`ponsd` logs `decides: owner policy`. Its rows, in order:

1. The probe id, for any subject: deny.
2. No subject: deny.
3. An action outside the vocabulary, or about another kind: deny.
4. `connector.read` of a catalog connector: allow.
5. A list: allow, filtered to the caller's own.
6. A stored connection or added connector whose owner is the caller,
   any action: allow.
7. A create that names no owner, or names the caller: allow.
8. Anything else: deny.

It has no administrators and sets no limits; the installation's own
limits of [Configuration](configuration.md#limits) still hold. A token
that carries grants, a personal access token narrowed by its holder in
the RFC 9396 `authorization_details` claim, narrows the policy's allow
to what those grants cover, and never widens it.

The owner policy suits one person, or a team where everyone acts for
themselves. A service that connects for its users, a push held to an
agent's branches, or read-only access for some callers needs an
endpoint of your own.

## In Go

`authorizer.Actions()` lists every action, `authorizer.Kind(action)` is
the resource kind an action is about, `authorizer.Fields(action)` lists
the members it may send beside the kind and the id, and
`authorizer.SendsID(action)` whether it sends the id of a stored
object. `authorizer.Vocabulary()` is the whole table
for a shared authorizer scaffold or conformance suite to validate
against. The limits of an answer are `authorizer.Limits`:

```go
limits, err := json.Marshal(authorizer.Limits{
	Refs:           []string{"refs/heads/agents/*"},
	CallsPerMinute: 600,
})
// {"refs":["refs/heads/agents/*"],"calls_per_minute":600}
```

`authorizer.DecodeLimits` reads limits the way Pons does, so an
endpoint's tests can hold its answers to it: a key Pons does not know,
such as `ref`, is an error there as it is a failed request in Pons.

An action string never changes and never disappears within a major
version of the module, and a limits member keeps its name and its
meaning.
