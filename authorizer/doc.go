// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package authorizer is the vocabulary an authorization endpoint for Pons
// is written against: the actions ponsd asks, the resource kind each one
// acts on, the fields a resource carries, and the limits an allow may
// carry. Import it to write the endpoint PONS_AUTHORIZER_URL points at, in
// Go, without keeping a copy of the strings.
//
// The envelope on the wire is latere.ai/x/pkg/authz's, and this package
// declares none of it: ponsd posts a request with the caller's subject, its
// claims, an action and a resource, and reads back an allow or a deny.
// Vocabulary is the whole action table as an authz.Vocabulary, which the
// client refuses an unknown action against, latere.ai/x/pkg/authz/server
// validates against, and latere.ai/x/pkg/authz/conformance drives its cases
// from:
//
//	conformance.Run(t, url, token, conformance.WithVocabulary(authorizer.Vocabulary()))
//
// Every action answers a decision, the two lists included: the allow of a
// list may carry a filter that narrows it to owners. A filter that names
// labels cannot be applied, since nothing in Pons is labeled.
//
// A subject is the issuer and the sub joined, "https://issuer.example.com|alice",
// and the claims are the token's, verbatim. Pons reads none of them.
//
// The resource carries its fields flat beside its kind and id, under the
// names of the Field constants; Fields lists the fields each action may
// send, and SendsID whether it sends the id of a stored object. No field
// is named kind or id, which the envelope keeps for the resource itself.
// A field Pons does not know for a request is absent, never empty.
//
// An allow may carry limits, the Limits type in its JSON form. A member the
// endpoint does not set is left out. DecodeLimits is the reading half, and
// is here so an endpoint's tests can hold their answers to it: an unknown
// key, a figure below zero and an empty glob are each errors, and ponsd
// fails the request closed.
//
// The promise, as for every public package of this module: additive within
// a module major. An action string never changes and never disappears, a
// resource kind stays the kind it is, and a limits member keeps its wire
// name and its meaning.
package authorizer
