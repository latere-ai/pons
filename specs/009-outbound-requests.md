---
title: "Outbound requests: the one dialer, public addresses only, redirects, limits, and a credential bound to its hosts"
status: drafted
track: core
depends_on:
  - specs/001-architecture.md
affects: [internal/dial/, catalog/, internal/config/]
effort: large
created: 2026-10-12
updated: 2026-10-12
author: changkun
---

# Outbound requests

## Overview

Pons opens connections to addresses it did not choose. A connector's
address comes from the operator's catalog or from a person, and the
addresses of a sign-in come from documents the connector and its
authorization server publish. Any of them can name the installation's
own network: a database, a metadata service, a neighbor's workload.
Every such request is also a place where a credential could be sent to
the wrong host.

This spec fixes the one package that opens such a connection, the rule
it applies to an address at the moment it connects, what it does with a
redirect, the bounds on what it reads, and the rule that attaches a
credential to a request.

## Current state

Nothing is built.

Two designs in sibling projects are the precedent. A document service
fetches a file from an address a caller names and checks the address at
the socket, after the name is resolved, on the first connection and
after every redirect. A sandbox control plane refuses an IP literal, a
single label and a private range in the hosts a secret is bound to, so
that a secret cannot be aimed at the cluster, matches hosts with
`latere.ai/x/pkg/hostmatch`, and refuses loopback targets at its egress
gateway. Pons takes the socket check from the first and the host rule
and the matcher from the second. Two things are new here: a name is
refused whole when any one of its addresses is not public, and the
credential is attached by the dialer and not by its callers.

## Design

### What goes through the dialer

`internal/dial` is the only package of the module that builds an HTTP
client, a transport or a `net.Dialer`. It offers two clients.

The **outside client** carries every request to an address that came
from the catalog, from a person, or from a document another service
published. Every rule of this spec applies to it.

| Request | Asked by | Redirects | Carries | Bounds |
|---|---|---|---|---|
| the protected resource metadata, the authorization server's metadata | [[007-sign-in]] | at most 3 | nothing | a fetch's |
| registering Pons as a client | [[007-sign-in]] | none | nothing | a fetch's |
| the token endpoint: a code, a refresh, a client's own grant | [[007-sign-in]] | none | the sign-in's secrets | a fetch's |
| revocation | [[007-sign-in]] | none | the token | a fetch's |
| the probe of a sign-in or a key, and every forwarded call | [[008-carrying-a-call]] | none | nothing, or the connection's credential | the carrier's |

The **operator client** carries requests to the addresses the operator
wrote into the configuration: the issuer's key set and the authorizer
([[004-identity-and-authorization]]). No address rule applies to it,
because an authorizer usually sits on the installation's own network
and the operator named it. Only `internal/access` takes it. The
database driver and the telemetry exporter open their own connections
to addresses the operator configured, and are the two exceptions the
test over the call sites names. Pons requests nothing else: it fetches
no icon and follows no link a document or an answer holds.

### A URL before its name is resolved

Every URL the outside client is handed passes four checks that need no
network:

1. The scheme is `https`.
2. It carries no user and no password.
3. Its host passes the host rule below.
4. Its port is 443, or a port the connector's catalog entry names: the
   port of its `url`, or of an address its `auth` members name
   ([[006-catalog]]). An address a document names is on 443 unless the
   entry names its port too. A connector a person adds is 443 only.

The host rule is the catalog's ([[006-catalog]]): one function of the
public package `catalog`, which imports nothing that dials, so the
catalog's validation, the route that adds a connector and the dialer
call the same one. A host is compared in lower case, without a trailing
dot and without its port. The rule refuses:

- anything `hostmatch.ValidPattern` refuses with no option: a single
  label, an IPv6 literal, a name that is not ASCII, a wildcard anywhere
  but one leading `*.` in front of two or more labels;
- an IP literal, including the notations a resolver reads as an IPv4
  address and `netip` does not, such as `10.1` and `0x7f.1`: a host
  whose last label is all digits or begins with `0x`;
- `localhost`, and every name under `localhost`, `local`, `internal`
  and `home.arpa`.

A pattern may carry the leading `*.`. The host of a URL may not. An
internationalized name is written in its ASCII form.

The connection is TLS 1.2 or later, and the certificate is verified
against the process's roots for the name of the URL. No code turns
verification off, which a test over the source holds. The dialer sets
`Host` from the URL and a caller cannot pass another, so the name that
was checked, the name on the certificate, the `Host` header and the
name a credential is bound to are one name.

### Public addresses only

The check is made on addresses, by the code that connects:

1. The name is resolved once, with the process's resolver.
2. The connection is refused unless every address of the answer is
   public. A name that answers with one public address and one private
   address is refused whole.
3. The dialer connects to the checked addresses, in the order answered,
   by address. The name is not resolved again for this connection, so a
   name that answers differently a second time gains nothing.
4. The socket's control hook, which is given the literal address about
   to be connected, applies the same table once more, so no path inside
   `internal/dial` connects unchecked.

A kept connection stays on the address checked when it was opened. A
new connection resolves and checks again. Pons caches no answer.

An address is public when it is in none of these blocks:

| Block | What it is |
|---|---|
| `0.0.0.0/8` | the unspecified address and "this network" |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private |
| `100.64.0.0/10` | carrier-grade NAT |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local, the metadata address `169.254.169.254` included |
| `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24` | set aside: protocol assignments, documentation, benchmarking |
| `224.0.0.0/4`, `240.0.0.0/4` | multicast; reserved, broadcast included |
| `::/128`, `::1/128` | unspecified, loopback |
| `::ffff:0:0/96` | IPv4-mapped: judged as the IPv4 address it holds |
| `64:ff9b::/96` | translated: judged as the IPv4 address in its last 32 bits |
| `64:ff9b:1::/48`, `2001::/32`, `2002::/16`, `2001:db8::/32` | local translation, tunnels that hold an IPv4 address, documentation |
| `fc00::/7` | unique local, a metadata address under it included |
| `fe80::/10`, `fec0::/10`, `ff00::/8` | link-local, the retired site-local range, multicast |

The table is one function, `dial.Public(netip.Addr) bool`, and nothing
else in the module judges an address. It reads no text: its argument is
the value the resolver returned or the socket is about to use, so no
notation of an address reaches a parser of Pons's own.

### Redirects

No secret is ever on a request that follows a redirect, so none is ever
sent on one:

- **The carrier follows none.** A `3xx` from a connector is `502
  connector_unavailable`, and the request is not sent anywhere else.
- **A request that carries a secret follows none.** A `3xx` from a
  token, registration or revocation endpoint fails that step.
- **A discovery fetch follows at most 3.** It is a `GET` that carries
  nothing. Each hop is a new request: the four checks, a new resolution
  and a new address check. A hop to `http` or to an address that is not
  public ends the fetch with that rule's reason, and a fourth hop ends
  it with `too_many_redirects`.

### A credential bound to its hosts

A caller of the dialer never writes a secret into a request. It passes
a `dial.Secret` beside the request: the value, the place it goes (a
header and its format, or a member of a form body) and a
`hostmatch.Matcher` of the hosts it may be sent to. The dialer writes
the value in as its last step before the request is sent, and only when
the scheme is `https`, the host matches and the port passed the port
rule. Otherwise the request is not sent, with the reason
`host_not_bound`. The matcher takes an exact name, or any name under a
`*.` pattern at any depth and never the name itself.

| Secret | Bound to |
|---|---|
| a connection's credential: an access token, a key, a token a client's own grant minted | the connector's `hosts`; the one host of its `url` when the entry lists none |
| the sign-in's secrets: a code with its verifier, a refresh token, a client secret | the one host of the endpoint recorded from validated metadata with the flow or the credential ([[007-sign-in]]) |

A catalog entry whose `hosts` do not match the host of its own `url` is
refused when the catalog is read. The outside client keeps no cookie:
a `Set-Cookie` is never stored and never sent back. It adds no trace
header to a request that leaves the installation.

### Limits

| Limit | Value | Applies to |
|---|---|---|
| resolving, connecting and the TLS handshake, together | 10 seconds | every connection |
| response headers | 64 KiB | every response |
| a metadata fetch, whole, its redirects included | 15 seconds | discovery |
| a request of the sign-in that carries a secret | the time [[007-sign-in]] gives it, at most 15 seconds | registration, the token endpoint, revocation |
| the body of a fetch, counted after a content coding is undone | 1 MiB | all of the sign-in's requests |
| the header wait, the idle time and the sizes of a call | the carrier's ([[008-carrying-a-call]]) | every forwarded call |

A body over its bound ends the request with `response_too_large`. It is
never cut short and used. Each value is one constant of `internal/dial`.

### A proxy

No proxy is read from the environment: `HTTP_PROXY`, `HTTPS_PROXY` and
`NO_PROXY` change nothing. `PONS_OUTBOUND_PROXY`, an `http` or `https`
URL, sends every request of the outside client through the operator's
own proxy as a tunnel to the name and the port. The four checks, the
resolution and the address check still run inside Pons first, and a
name with an address that is not public is never handed over.

The proxy resolves the name again, so behind a proxy Pons no longer
connects to the address it checked. The proxy must apply the same rule
and refuse every block of the table at the moment it connects. Its own
address is the operator's and is not judged. The server logs at start
that a proxy is in use, and never its user or password.

### The switch for stubs

`PONS_DIAL_ALLOW_PRIVATE=1` makes the dialer treat every address as
public and allow every port, so that a server can be run against stubs
on loopback ([[011-distribution]]). Everything else stays: https, the
certificate, the host rule, redirects, bindings and limits. The server
logs it at start at warning level, `ponsd check` reports it, and
`/readyz` carries it. It is never a default, and no manifest sets it.

`dial.New` takes three options no configuration variable sets: a
`Permit` function over an address and a port, a resolver, and a pool of
roots. The switch is a `Permit` that admits everything. The e2e tier
names each stub under `example.com` through the resolver, trusts the
stubs' authority through the roots, and permits the stubs' listeners
alone, so a refused address and a served call are tested on one server.

### Three layers

1. **When written.** In the catalog and on a connector a person adds,
   a `url` passes the four checks and every host pattern passes the
   host rule. Otherwise the catalog does not load, and the request is
   `400 invalid_field` ([[006-catalog]]).
2. **When connected.** The dialer's address check, on the address used.
3. **Around the process.** An installation's network rule denies egress
   to the private ranges ([[011-distribution]]).

The second is the defense. The first is a clear error before anything
is stored, and the third holds if the second has a bug.

### Refusals

| Name | `details.reason` | Kind |
|---|---|---|
| `scheme_not_https` | the address is not an https address | rule |
| `host_not_a_name` | the host is an address, a single label or a reserved name | rule |
| `port_not_allowed` | the port is not 443 or one the catalog names | rule |
| `address_not_public` | the name resolves to an address that is not public | rule |
| `certificate_not_verified` | the certificate does not verify for the name | rule |
| `redirect_refused` | the other side answered with a redirect, and none is followed here | rule |
| `too_many_redirects` | more than 3 redirects | rule |
| `host_not_bound` | the credential is not bound to this host | rule |
| `response_too_large` | the answer is over its bound | rule |
| `resolve_failed`, `connect_failed`, `timeout` | the name did not resolve; no connection could be opened; the other side did not answer in time | failure |

At a sign-in or an add, a refusal or a failure is `422
connector_unreachable`. On a call it is `502 connector_unavailable`,
and a timeout is `504 connector_timeout`. `details.reason` is the fixed
sentence of the table: it names the rule and never a resolved address,
a redirect's target or any part of an answer, so a refusal is no map of
the installation's network. `retryable` is false for a rule and true
for a failure. Refusals and failures are counted by name
([[010-records-and-observability]]).

## Not in this spec

What the carrier forwards and removes ([[008-carrying-a-call]]); the
order of discovery, the validation of a metadata document and which
endpoint a secret belongs to ([[007-sign-in]]); how the catalog writes
`hosts` and a port ([[006-catalog]]); the manifest of the network rule
([[011-distribution]]); paths under a connector's address
([[014-http-forwarding]]).

## Acceptance criteria

| Criterion | Test that proves it |
|---|---|
| No package but `internal/dial` builds an HTTP client, a transport or a dialer, and no package but `internal/access` takes the operator client | `TestOnlyTheDialerDials`, over `go list -deps` and call sites |
| Every block of the table is refused, a mapped and a translated form of each IPv4 block included, and an address outside every block is admitted | `dial.TestPublic` |
| A name with one address that is not public is refused whole, before any connection is opened | `dial.TestAnyPrivateAnswerRefusesTheName` |
| A name that answers differently a second time is asked once per connection, and the socket reaches the address that was checked | `dial.TestConnectsToTheAddressItChecked` |
| An `http` URL, a URL with a user, an IPv4 literal in each notation, an IPv6 literal, a single label, `localhost` and a name under each reserved suffix are refused with no name resolved; a port other than 443 is refused unless the catalog entry names it, and always for a connector a person added | `catalog.TestHostRule`, `dial.TestChecksBeforeResolving`, `dial.TestPorts` |
| The catalog's validation, the add route and the dialer call one host rule, and a catalog entry whose `hosts` miss its own `url` does not load | `TestTheHostRuleHasOneImplementation`, `catalog.TestHostsCoverTheURL` |
| A certificate for another name, an expired one and one from an unknown authority are refused, and no source file turns verification off | `dial.TestCertificateIsVerifiedForTheName`, `TestNothingTurnsVerificationOff` |
| A `3xx` to a forwarded call is `502 connector_unavailable` and nothing is sent to its target; a discovery fetch follows 3 hops and not a fourth, and refuses a hop to `http` or to a private address | `TestCarrierFollowsNoRedirect`, `dial.TestRedirects` |
| A secret is written only into an `https` request whose host matches its binding, a request to any other host is not sent, and a caller's own `Host` is replaced; the outside client stores no cookie and sends no trace header to a connector | `dial.TestSecretIsBoundToItsHosts`, `dial.TestNoCookieAndNoTraceHeaderLeave` |
| Headers over 64 KiB, a fetch's body over 1 MiB after decoding, a connect past 10 seconds and a metadata fetch past 15 seconds each end with their reason | `dial.TestLimits` |
| A proxy variable of the environment is ignored; with `PONS_OUTBOUND_PROXY` every outside request leaves through the proxy, and a name with a private address is never handed to it | `dial.TestNoProxyFromTheEnvironment`, `dial.TestOutboundProxy` |
| With `PONS_DIAL_ALLOW_PRIVATE=1` the start logs a warning, and `ponsd check` and `/readyz` report it; without it a stub on loopback is refused | `TestAllowPrivateIsLoud` |
| A refusal answers the code of its route with the fixed sentence of its rule, and no member of any response holds a resolved address | `TestRefusalsNameTheRuleAndNoAddress` |
