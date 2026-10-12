// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package dial is the one dialer of specs/009-outbound-requests.md, and the
// only package of the module that builds an HTTP client, a transport or a
// net.Dialer. It offers two clients: the outside client, toward every
// address a catalog entry, a person or another service's document named,
// which reaches public addresses only and attaches a credential to its
// hosts alone; and the operator client, toward the addresses the operator
// configured.
package dial

import "time"

// The limits of specs/009-outbound-requests.md, one constant each.
const (
	// connectTimeout bounds resolving, connecting and the TLS handshake,
	// together.
	connectTimeout = 10 * time.Second
	// maxHeaderBytes bounds the headers of every response.
	maxHeaderBytes = 64 << 10
)
