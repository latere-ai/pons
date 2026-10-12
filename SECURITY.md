# Security

Pons holds other people's credentials for services it does not run, and
connects to addresses it did not choose. This file is what the project
promises about that, what it does not, and how to tell us when it is
wrong.

## Reporting a vulnerability

Report one to security@latere.ai. Do not open a public issue for it. You
will hear back within three business days.

## State

Pons has no release yet. The design is in [`specs/`](specs/README.md),
and the threat model is
[`specs/012-security-and-threat-model.md`](specs/012-security-and-threat-model.md).
The commitments below are the ones the code already holds, each with the
test that holds it. The list grows with the code; a control without a
test is a claim, and no claim is listed here.

| Who | What Pons commits to | Proved by |
|---|---|---|

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
- **A client that gives a finish code away,** or a caller's token taken
  from the caller. Pons cannot tell the holder from the owner.
- **A catalog written wrongly:** hosts wider than the service's own, or a
  tool that changes something marked as one that only reads.
- **An authorization server that ignores the resource it is told a token
  is for** and issues a token valid at another resource. Pons names the
  connector in every request and cannot see what the server bound the
  token to.
- **Denial of service** beyond the bounds the threat model names.
