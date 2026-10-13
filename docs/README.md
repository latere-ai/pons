# Documentation

For people who run `ponsd`, write its catalog, build an app that
connects services through it, or write the authorizer it asks.

## Trying it

| Page | |
|---|---|
| [Running it locally](local.md) | `ponsd` on your machine with a local issuer, a connection to a public service, and a call through the forwarding address and the git address |

## Running it

| Page | |
|---|---|
| [Install](install.md) | the image, Postgres and its pooler, the sealing keys and their rotation, sign-in addresses, the probes, `ponsd check`, the network, and upgrading |
| [Configuration](configuration.md) | every `PONS_*` variable, its default, and what refuses a start |
| [The catalog](catalog.md) | every member of an entry, each kind and way to give access, secrets, hosts, the issuer rule of a sign-in, the example file, and the GitHub entry |
| [Security](security.md) | what Pons guarantees, what it does not defend, and what an operator keeps safe |

## Building against it

| Page | |
|---|---|
| [API](api.md) | authentication, connecting with a key or a sign-in, reconnecting, disconnecting, call records, the forwarding and git addresses, and the errors to branch on |
| [Writing an authorizer](authorizer.md) | the question Pons asks, the vocabulary, the limits an allow carries, failing closed, and the owner policy |

The OpenAPI document is [`api/openapi.yaml`](../api/openapi.yaml), and
every installation serves it at `GET /v1/openapi.yaml`, under its base
path.

## Changing it

[`CONTRIBUTING.md`](../CONTRIBUTING.md) is how to build and test a change
and how the code is organized. [`SECURITY.md`](../SECURITY.md) is how to
report a vulnerability.
