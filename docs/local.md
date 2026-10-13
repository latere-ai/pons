# Running it locally

`ponsd` on your own machine: built from source, a local OpenID Connect
issuer, a catalog with one connector, a connection, and a call through
each of its addresses with `curl` and `git`. Nothing here survives a
restart: with no database, `ponsd` keeps everything in the process.

`ponsd` has no development mode and no static token. Every request needs
a token from an OpenID Connect issuer, so a local run needs one too.
This page uses [Dex](https://dexidp.io/) in a container. Any issuer
works whose discovery document `ponsd` can read and whose tokens are
signed with RS256 or ES256 and name the audience `pons`.

The blocks run in order in one shell, from the root of a clone.

## What you need

Go 1.27 or newer, `git`, `curl`, `jq`, `openssl`, and Podman or Docker.
The commands say `podman`; `docker` takes the same arguments.

## Build

```sh
make build
./out/ponsd version
```

## An issuer

Dex with one user, `alice@example.com` with the password `password`,
and one client whose id is `pons`. Dex addresses its ID tokens to the
client that asked, so a token for the client `pons` carries the audience
`ponsd` accepts by default.

```sh
mkdir -p local
cat > local/dex.yaml <<'EOF'
issuer: http://127.0.0.1:5556/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  passwordConnector: local
enablePasswordDB: true
staticPasswords:
  - email: alice@example.com
    # bcrypt of "password"
    hash: "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
    username: alice
    userID: alice
staticClients:
  - id: pons
    name: Pons
    secret: local-client-secret
    redirectURIs: ["http://127.0.0.1:5555/callback"]
EOF

podman run -d --name pons-dex -p 127.0.0.1:5556:5556 \
  -v "$PWD/local/dex.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:v2.43.1 dex serve /etc/dex/config.yaml
```

The password grant gives a token without a browser:

```sh
until curl -fs http://127.0.0.1:5556/dex/.well-known/openid-configuration > /dev/null; do sleep 1; done
TOKEN=$(curl -s http://127.0.0.1:5556/dex/token -u pons:local-client-secret \
  -d grant_type=password -d username=alice@example.com -d password=password \
  -d scope=openid | jq -r .id_token)
```

`ponsd` accepts a token until it expires and for at most 24 hours after
it was minted; run the last command again for a fresh one. The caller
it names is the issuer and the token's `sub` joined by a pipe,
`http://127.0.0.1:5556/dex|<sub>`, and that string is the owner of
every connection the token makes.

## A catalog

One connector: GitHub's API and its git host, for public repositories,
with no credential. It needs no account anywhere, and it shows both
addresses working. [The catalog](catalog.md) describes every member.

```sh
cat > local/catalog.yaml <<'EOF'
connectors:
  - name: github-public
    title: GitHub, public repositories
    description: Read public repositories without signing in.
    kind: http
    url: https://api.github.com
    git: {url: https://github.com}
    hosts: ["api.github.com", "github.com"]
    auth: {type: none}
EOF
```

## Start ponsd

```sh
PONS_PUBLIC_URL=http://localhost:8080 \
PONS_OIDC_ISSUERS=http://127.0.0.1:5556/dex \
PONS_SEALING_KEYS="$(openssl rand -base64 32)" \
PONS_CATALOG_FILE=local/catalog.yaml \
  ./out/ponsd serve 2> local/ponsd.log &

until curl -fs http://localhost:8080/readyz > /dev/null; do sleep 1; done
```

`PONS_PUBLIC_URL` may be `http://` here because no database is
configured; with one, `ponsd` requires `https://`. The log, one JSON
object per line, says the store is in memory and that the owner policy
decides: with no authorizer configured, each caller reaches the
connections it owns and nothing else.

`make run` builds and starts the same server with `PONS_PUBLIC_URL` set
for you, and reads the other variables from your environment.

## Connect and call

The catalog, as a caller sees it:

```sh
curl -s http://localhost:8080/v1/connectors -H "Authorization: Bearer $TOKEN" | jq '.items[].name'
```

Connect it. A connector that takes no credential is connected at once:

```sh
CONNECTION=$(curl -s http://localhost:8080/v1/connections \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"connector": "github-public"}')
echo "$CONNECTION" | jq '{id, state, address, git_address}'
ID=$(echo "$CONNECTION" | jq -r .id)
ADDRESS=$(echo "$CONNECTION" | jq -r .address)
GIT_ADDRESS=$(echo "$CONNECTION" | jq -r .git_address)
```

Call the API through the forwarding address, and clone through the git
address. Both take your token, never GitHub's:

```sh
curl -s "$ADDRESS/repos/latere-ai/pons" -H "Authorization: Bearer $TOKEN" | jq '{full_name, license: .license.spdx_id}'
git -c http.extraHeader="Authorization: Bearer $TOKEN" clone --depth 1 "$GIT_ADDRESS/latere-ai/pons.git" local/pons
```

Each request left a record:

```sh
curl -s "http://localhost:8080/v1/connections/$ID/calls" -H "Authorization: Bearer $TOKEN" \
  | jq -c '.items[] | {method, tool, effect, outcome, status}'
```

## A key instead

To try a pasted key, give the entry `auth: {type: token}` for a service
you hold a key for, restart `ponsd`, and connect with the key:

```sh
curl -s http://localhost:8080/v1/connections \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"connector": "<name>", "credential": {"value": "<the key>"}}'
```

A key for a connector of kind `http` is tried once with a `GET` of the
entry's `url` before it is kept. A key the service refuses with `401` or
`403` answers `422 credential_refused`, and nothing is stored. The key
goes in `Authorization: Bearer` by default; [the catalog](catalog.md#a-pasted-key)
says how to place it elsewhere.

## A sign-in

A sign-in starts from a local run too, when the service has an OAuth
application of yours whose callback is
`http://localhost:8080/v1/callback`, and `PONS_RETURN_URLS` names the
address your browser should come back to. The connect answers an
`authorization_url` whose `redirect_uri` is that callback.
[The catalog](catalog.md#github) has the GitHub entry, and
[the API](api.md#by-signing-in) the steps after it.

## Stopping

```sh
kill %1
podman rm -f pons-dex
rm -rf local
```

## What next

- [Install](install.md): the image, Postgres, and the sealing keys of an
  installation that keeps what it holds.
- [Writing an authorizer](authorizer.md): who may connect what, and what
  a caller may do through a connection.
