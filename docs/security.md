# Security

What Pons promises the people whose credentials it holds and the
operator who runs it, in plain terms. [SECURITY.md](../SECURITY.md) is
the policy: what Pons commits to against each kind of attacker, what is
out of scope, and how to report a vulnerability. Report one to
security@latere.ai, never as a public issue.

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

**Every request is verified and asked about.** Each carries a token from
an issuer the operator listed, and nothing acts before the authorizer,
or the owner policy, has decided. A connection somebody else owns
answers exactly as one that does not exist.

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

## What Pons does not defend

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
  own.

## For an operator

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
- List in `PONS_RETURN_URLS` only the addresses of your own app.
