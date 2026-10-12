// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"strings"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
)

// ReasonUnknownAction is the deny of an action outside the vocabulary, or of
// one asked about another kind than it acts on. The other reasons the owner
// policy denies with are the shared contract's: probe, anonymous, not_owner
// and grant.
const ReasonUnknownAction = "unknown_action"

// OwnerPolicy is what decides with PONS_AUTHORIZER_URL unset. Its rows, in
// the order they are tried:
//
//   - the probe id, as any subject: deny, probe;
//   - no subject: deny, anonymous;
//   - an action outside the vocabulary, or asked about another kind: deny,
//     unknown_action;
//   - a read of a catalog connector: allow;
//   - a list: allow, with a filter that narrows it to the subject's own;
//   - a stored connection or added connector whose owner is the subject,
//     any action: allow;
//   - a create that names no owner, or names the subject: allow;
//   - anything else: deny, not_owner.
//
// The policy has no administrators and names no limit of its own. Its
// answer is narrowed by the grants of the caller's token, as an
// authorizer's is.
type OwnerPolicy struct{}

// Authorize answers one request, so the owner policy and an operator's
// endpoint are one seam to everything above. A token whose grants cannot be
// read is denied: its reach is unknown, and the closed answer is a deny.
func (p OwnerPolicy) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	d := p.decide(req)
	if !d.Allow {
		return d, nil
	}
	grants, err := authz.ParseGrants(req.Claims)
	if err != nil {
		return authz.Decision{Reason: authz.ReasonGrant}, nil
	}
	return authz.Restrict(authorizer.Core, d, req, grants), nil
}

// Decide is Authorize under the name latere.ai/x/pkg/authz/server calls a
// decider by, so the policy ponsd runs in process is also an endpoint an
// operator can serve.
func (p OwnerPolicy) Decide(ctx context.Context, req authz.Request) (authz.Decision, error) {
	return p.Authorize(ctx, req)
}

// decide is the policy's own answer, before the grants narrow it.
func (OwnerPolicy) decide(req authz.Request) authz.Decision {
	kind := authorizer.Kind(req.Action)
	switch {
	case strings.EqualFold(req.Resource.ID, authz.ProbeID):
		return authz.Decision{Reason: authz.ReasonProbe}
	case req.Subject == "":
		return authz.Decision{Reason: authz.ReasonAnonymous}
	case kind == "" || kind != req.Resource.Kind:
		return authz.Decision{Reason: ReasonUnknownAction}
	}
	owner := req.Resource.String(authorizer.FieldOwner)
	allow := authz.Decision{Allow: true}
	switch req.Action {
	case authorizer.ActionConnectorRead:
		if req.Resource.ID == "" && owner == "" && req.Resource.String(authorizer.FieldName) != "" {
			return allow // a catalog connector is the installation's
		}
	case authorizer.ActionConnectorList, authorizer.ActionConnectionList:
		return authz.Decision{Allow: true, Filter: &authz.Filter{Owners: []string{req.Subject}}}
	}
	switch {
	case req.Resource.ID != "":
		// A stored object always has an owner; one with none is a resource
		// the handler did not finish, and is nobody's.
		if owner != "" && owner == req.Subject {
			return allow
		}
	case req.Action == authorizer.ActionConnectionCreate || req.Action == authorizer.ActionConnectorCreate:
		if owner == "" || owner == req.Subject {
			return allow
		}
	}
	return authz.Decision{Reason: authz.ReasonNotOwner}
}
