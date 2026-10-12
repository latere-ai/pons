// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package dial is the one dialer of specs/009-outbound-requests.md, and the
// only package of the module that builds an HTTP client, a transport or a
// net.Dialer. It offers two clients: the outside client, toward every
// address a catalog entry, a person or another service's document named,
// which reaches public addresses only and attaches a credential to its
// hosts alone; and the operator client, toward the addresses the operator
// configured.
//
// The outside client checks a URL before its name is resolved (the scheme,
// a user part, the host rule of the catalog package, the port), resolves the
// name once, refuses the name whole when any of its addresses is not public,
// connects to the checked addresses by address, and checks the literal
// address once more in the socket's control hook. A secret is never written
// by a caller: it is handed to the dialer beside the request, and the dialer
// writes it in last, toward a host it is bound to.
package dial

import "time"

// The limits of specs/009-outbound-requests.md, one constant each.
const (
	// connectTimeout bounds resolving, connecting and the TLS handshake,
	// together.
	connectTimeout = 10 * time.Second
	// maxHeaderBytes bounds the headers of every response.
	maxHeaderBytes = 64 << 10
	// fetchTimeout bounds a metadata fetch, whole, its redirects included.
	fetchTimeout = 15 * time.Second
	// secretTimeout bounds a request of the sign-in that carries a secret:
	// the time the sign-in gives it, and never more than this.
	secretTimeout = 15 * time.Second
	// maxFetchBody bounds the body of a fetch, counted after a content
	// coding is undone.
	maxFetchBody = 1 << 20
	// maxRedirects is how many redirects a discovery fetch follows.
	maxRedirects = 3
)
