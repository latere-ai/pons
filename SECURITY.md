# Security

Pons holds other people's credentials for services it does not run, and
connects to addresses it did not choose. This file is what the project
promises about that, what it does not, and how to tell us when it is
wrong. [`docs/security.md`](docs/security.md) says the same for the
people who use and run it.

## Reporting a vulnerability

Report one privately, through
[GitHub's private vulnerability reporting](https://github.com/latere-ai/pons/security/advisories/new)
or by email to security@latere.ai. Do not open a public issue for it. The
[organization's security policy](https://github.com/latere-ai/.github/blob/main/SECURITY.md)
sets the response times, how disclosure works, and the safe harbor for
research done in good faith. Credit in the release notes on request.

Fixes ship in the next release of the current major line, as the
organization's policy on
[supported versions](https://github.com/latere-ai/.github/blob/main/SECURITY.md#supported-versions)
says; the [releases page](https://github.com/latere-ai/pons/releases)
lists them.

The reports we most want: a credential that reaches a caller, a
response, a log line or the database in the clear; a call through a
connection that the authorizer did not allow; a request that leaves a
connection's service, or that Pons sends to a private address; and a
connection someone else owns that answers differently from one that
does not exist. What [is not defended](#what-is-not-defended) is not a
vulnerability, but a report that one of those limits is wider than
written here is.

## What is protected

Pons is attacked from six places: a caller with a token of its own, a
session steered by what it read, a reader of its database or its logs,
a service it carries calls to, an address aimed at the installation's
own network, and a caller that tries to exhaust it. Each commitment
below is held by the named tests, which run on every change. The tests
of the git address run a real `git` and skip where it is not installed.

| Against | What Pons commits to | Held by |
|---|---|---|
| a caller with a valid token of another owner | every route below the base path verifies the token and asks the authorizer before it reads or acts, except the sign-in callback, the client documents Pons names itself with, the OpenAPI document and `version`; with no authorizer, an owner reaches their own connections alone; a connection someone else owns answers exactly as one that does not exist | `TestRoutesNeedABearer`, `TestEveryRouteAsksItsAction`, `TestTheOwnerPolicy`, `TestAnotherOwnersTokenReachesNothing`, `TestADenyDoesNotConfirmAnId`, `TestNothingTellsAnIdBeforeTheQuestion` |
| a caller when the authorizer cannot answer | a request that would change something does nothing and is refused; an authorizer that allows the reserved probe stops the start | `TestADenyAndAnOutageAnswerBeforeAnythingIsDone`, `TestTheClientFailsClosed`, `TestTheServerRefusesAnEndpointThatAllowsTheProbe` |
| a reader or a writer of the database | every credential is ciphertext under a key the database never holds, bound to its row; copied to another row it does not open, and neither does one whose endpoints or connector address were rewritten | `TestNoPlaintextAtRest`, `TestAConnectorsSecretIsSealed`, `TestACopiedCiphertextDoesNotOpen`, `TestRewrittenEndpointDoesNotOpen`, `TestOpenIsConfined` |
| a reader of responses and logs | a pasted key, an issued token and a client's secret appear in no response, header, log line or database row, and reach only the hosts of the connector they belong to, in the place it names | `TestNoCredentialLeavesButTowardItsConnector`, `TestSecretIsBoundToItsHosts`, `TestRequestHeaders`, `TestConnectorShowsNoSecretReference` |
| an address aimed at the installation's own network | an address a person adds is refused when it names an IP address, a private name or a port other than 443, and every request Pons makes to a service connects only to public addresses, checked on the address it connects to | `TestHostRule`, `TestRefusalsNameTheRuleAndNoAddress`, `TestAnyPrivateAnswerRefusesTheName`, `TestConnectsToTheAddressItChecked` |
| a caller of a connection's address | a path cannot climb out of the service's address, a redirect elsewhere is not followed, and the caller's own `Authorization` and every header not listed are removed | `TestAForwardedPathStaysOnItsConnector`, `TestARedirectStaysOnItsConnector`, `TestForwardedHeaders` |
| a caller allowed to push to some branches | a push naming a ref outside the allow's `refs` is refused before any of its pack is sent to the service, and git prints the rule as the reason | `TestAPushIsHeldToItsRefs` |
| an agent's session tricked by what it read | it never obtains a credential, whatever tool it calls with whatever arguments; a tool call outside the allow's `tools`, a writing tool under `read_only` and a tool the catalog hides are refused before the credential is opened; each call that reaches its connection is recorded with its session, its tool and its effect | `TestATrickedSessionObtainsNoCredential`, `TestParseOnlyTheMethodAndTool`, `TestLimitsOfAnAllow`, `TestACallLeavesOneRecord` |
| a service that answers with hostile intent | its sign-in challenge never reaches the caller, and the caller's token never reaches it; its redirect is not followed and its cookie is neither kept nor passed on; headers past 64 KiB end the call, an answer streams and is never held whole, and a stream that goes silent ends at its idle time | `TestAConnectorsChallengeReachesNoCaller`, `TestResponseHeaders`, `TestCarrierFollowsNoRedirect`, `TestAConnectorSetsNoCookie`, `TestAnAnswerIsBounded`, `TestStreamIsFlushedPerEvent` |
| a caller that tries to exhaust Pons | a request ends at its size bound and a slow service at its timeouts; requests in flight are bounded per connection, per caller and per process on each replica, so a slow service holds its own connection's places and no other's; many refused calls of one caller to one connection leave one record | `TestSizesAndTimeoutsEndACall`, `TestTimeoutsAndCancel`, `TestAForwardedBodyStreams`, `TestAConnectionsConcurrencyIsBounded`, `TestACallersConcurrencyIsBounded`, `TestDeniedCallsAreRecordedOncePerMinute` |

## What is not defended

- **An operator who holds the sealing keys.** They open every
  credential. Sealing defends against a reader of the database who lacks
  the keys, not against whoever runs the installation.
- **A service that misuses the access a person granted it.** Pons carries
  calls to the service a person chose. What that service does with the
  person's account is the service's.
- **An authorizer that answers wrongly,** or an issuer that signs a token
  for the wrong subject. Pons refuses when no decision arrives. It
  follows the decision that does. That includes the two reasons of a
  deny that Pons tells the caller, `kept_apart_from_google` and
  `name_unusable`: each says the connection exists, so an authorizer
  that sends one to a caller who does not hold the connection tells
  that caller so.
- **A compromised host.** The process's memory holds the sealing keys and
  the access tokens it has opened.
- **What a model does with an answer it read.** Pons bounds what a
  session tricked by content can do through Pons, not what it does
  elsewhere, and not what it tells the person it works for.
- **A client that gives a sign-in's one-time code away,** or a caller's
  token taken from the caller. Pons cannot tell the holder from the
  owner.
- **A catalog written wrongly:** hosts wider than the service's own, or a
  tool that changes something marked as one that only reads.
- **An authorization server that ignores the resource it is told a token
  is for** and issues a token valid at another resource. Pons names the
  connector in every request and cannot see what the server bound the
  token to.
- **An installation that sets `PONS_DIAL_ALLOW_PRIVATE`.** It treats
  every address as public, for a server run against test services on
  loopback, and removes the rule that keeps a connector from reaching
  the installation's own network.
- **A secret a caller puts in a forwarded call's path.** The call record
  keeps the path until its retention passes, though never the query
  string or a header.
- **Denial of service** beyond the limits an installation configures.
  The limits on requests in flight and on creates hold on each replica.

## Audit

Pons has had no external security audit. The commitments above are held
by tests in this repository, which run on every change.

## Supply chain

Dependencies are checked for known vulnerabilities on every push that
changes a Go package. A release is built from a tagged commit whose
verify run passed, through the shared release stages in
[latere-ai/ci](https://github.com/latere-ai/ci): the image is signed by
the build stage's identity, run for this repository, and the release
carries a bill of materials and `checksums.txt`, signed by the publish
stage's identity.

### Verifying a release

With `TAG` the release's tag:

```sh
gh release download "$TAG" -R latere-ai/pons -D pons-release
cd pons-release
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/latere-ai/ci/\.github/workflows/image-publish\.yml@' \
  --certificate-github-workflow-repository latere-ai/pons checksums.txt
sha256sum -c checksums.txt

cosign verify "ghcr.io/latere-ai/ponsd:$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/latere-ai/ci/\.github/workflows/image-build\.yml@' \
  --certificate-github-workflow-repository latere-ai/pons
gh attestation verify "oci://ghcr.io/latere-ai/ponsd:$TAG" -R latere-ai/pons \
  --signer-workflow latere-ai/ci/.github/workflows/image-build.yml
```

The release workflow runs the same checks against every release it
publishes.
