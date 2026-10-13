# Security

Pons holds other people's credentials for services it does not run, and
connects to addresses it did not choose. This file is what the project
promises about that, what it does not, and how to tell us when it is
wrong. [`docs/security.md`](docs/security.md) says the same for the
people who use and run it.

## Reporting a vulnerability

Report one to security@latere.ai. Do not open a public issue for it. You
will hear back within three business days.

## Commitments

- A credential is accepted once and never returned. It leaves Pons only
  toward the hosts its connector names, in the place the connector
  names.
- Every credential at rest is ciphertext under a key the database never
  holds, bound to the row it belongs to.
- Every request carries a token from an issuer the operator listed, and
  nothing acts before the authorizer, or the owner policy, has decided. A
  connection someone else owns answers exactly as one that does not
  exist.
- A decision the authorizer cannot give is a refusal, never an allow.
- Pons connects to the services it carries calls to on public addresses
  alone, and a request to a connection's address cannot leave that
  connection's service.

## What is protected, and what proves it

Each row is who could attack, what Pons commits to against them, and the
tests in this repository that hold it to its word. A control without a
test is a claim, and no claim is listed here. The list grows with the
code.

| Who | What Pons commits to | Proved by |
|---|---|---|
| a caller with a valid token of another owner | every route verifies the token and asks before it reads or acts; with no authorizer an owner reaches their own connections alone; a connection someone else owns answers exactly as one that does not exist | `TestADenyDoesNotConfirmAnId`, `TestTheOwnerPolicyThroughTheAPI`, `TestAnotherOwnersTokenReachesNothing` |
| a caller when the authorizer cannot answer | a request with no decision does nothing and is refused; an authorizer that allows the reserved probe stops the start | `access.TestTheClientFailsClosed`, `httpapi.TestADenyAndAnOutageAnswerBeforeAnythingIsDone`, `TestTheServerRefusesAnEndpointThatAllowsTheProbe` |
| a reader or a writer of the database | every credential is ciphertext under a key the database never holds, bound to its row; copied to another row it does not open, and neither does one whose endpoints or connector address were rewritten | `TestNoPlaintextAtRest`, `store.TestACopiedCiphertextDoesNotOpen`, `store.TestRewrittenEndpointDoesNotOpen` |
| a reader of responses and logs | a pasted key, an issued token and a client's secret appear in no response, header, log line or database row, and reach only the service they belong to | `TestNoCredentialLeavesButTowardItsConnector` |
| an address that aims at the installation's own network | an address a person adds is refused when it names an address, a private name or a port other than 443, and every request Pons makes to a service connects only to public addresses, checked on the address it connects to | `TestRefusalsNameTheRuleAndNoAddress`, `dial.TestConnectsToTheAddressItChecked`, `dial.TestAnyPrivateAnswerRefusesTheName` |
| a caller of a connection's address | a path cannot climb out of the service's address, a redirect elsewhere is not followed, the caller's own `Authorization` and every header not listed are removed | `carry.TestAForwardedPathStaysOnItsConnector`, `carry.TestARedirectStaysOnItsConnector`, `carry.TestForwardedHeaders` |
| a caller allowed to push to some branches | a push naming a ref outside the allow's `refs` is refused before any of its pack is sent | `carry.TestAPushIsHeldToItsRefs` |

## What is not defended

- **An operator who holds the sealing keys.** They open every
  credential. Sealing defends against a reader of the database who lacks
  the keys, not against whoever runs the installation.
- **A service that misuses the access a person granted it.** Pons carries
  calls to the service a person chose. What that service does with the
  person's account is the service's.
- **An authorizer that answers wrongly,** or an issuer that signs a token
  for the wrong subject. Pons refuses when no decision arrives. It
  follows the decision that does.
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
- **Denial of service** beyond the limits an installation configures.

## Supply chain

Dependencies are checked for known vulnerabilities on every push. A
release is built from a tagged commit whose verify run passed: the
image is signed by the release workflow's identity, and the release
carries a bill of materials with a signed checksum.
