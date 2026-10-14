// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/mcp"
)

// Plan is what one sign-in uses, found before the person is sent away and
// recorded with the flow: the validated issuer and endpoints, how Pons
// identifies itself, the resource a token is for and the scopes asked.
type Plan struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RevocationEndpoint    string
	// IssParameterSupported is whether the issuer's metadata says its
	// answer carries iss.
	IssParameterSupported bool
	ClientID              string
	Resource              string
	Scopes                []string
}

// unsupported is a document that was read and cannot be used, naming the
// step.
func unsupported(reason string) *apierr.Error {
	return apierr.Fail(apierr.CodeSignInUnsupported, reason)
}

// unreachable is a connector or a document that could not be fetched, or
// an address the dialer refuses, naming the rule.
func unreachable(err error) *apierr.Error {
	name, _, ok := dial.ReasonOf(err)
	if !ok {
		name = "fetch_failed"
	}
	return apierr.Fail(apierr.CodeConnectorUnreachable, name)
}

// Discover finds how a connector signs people in (specs/007-sign-in.md):
// the authorization server, its validated metadata, the client Pons is
// there, and the scopes and the resource the request names. requested are
// the scopes the request names beside the base. Nothing of it is cached.
func (s *Signin) Discover(ctx context.Context, conn Connector, requested []string) (Plan, error) {
	a := conn.Auth
	switch a.Discovery {
	case catalog.DiscoveryNone:
		p := Plan{
			Issuer: a.Issuer, AuthorizationEndpoint: a.AuthorizeURL, TokenEndpoint: a.TokenURL, RevocationEndpoint: a.RevokeURL,
			ClientID: a.Client.ID, Scopes: union(a.Scopes, requested),
		}
		if conn.ResourceFor() {
			p.Resource = conn.URL
		}
		return p, nil
	case catalog.DiscoveryIssuer:
		md, err := s.metadata(ctx, conn, a.Issuer)
		if err != nil {
			return Plan{}, err
		}
		p, err := s.planAt(ctx, conn, md)
		if err != nil {
			return Plan{}, err
		}
		if conn.ResourceFor() {
			p.Resource = conn.URL
		}
		p.Scopes = s.scopes(a.Scopes, requested, md)
		return p, nil
	}
	return s.byResource(ctx, conn, requested)
}

// byResource is discovery by the protected resource metadata (RFC 9728):
// the challenge of one request with no credential, else the well-known
// addresses, then each authorization server in the order listed.
func (s *Signin) byResource(ctx context.Context, conn Connector, requested []string) (Plan, error) {
	doc, challenged, err := s.resourceMetadata(ctx, conn)
	if err != nil {
		return Plan{}, err
	}
	var last error = unsupported("no_authorization_server")
	for _, issuer := range doc.AuthorizationServers {
		if conn.Auth.Issuer != "" && issuer != conn.Auth.Issuer {
			continue
		}
		md, err := s.metadata(ctx, conn, issuer)
		if err != nil {
			last = err
			continue
		}
		p, err := s.planAt(ctx, conn, md)
		if err != nil {
			last = err
			continue
		}
		if conn.ResourceFor() {
			p.Resource = doc.Resource
		}
		base := conn.Auth.Scopes
		if len(base) == 0 {
			base = challenged
		}
		if len(base) == 0 {
			base = doc.ScopesSupported
		}
		p.Scopes = s.scopes(base, requested, md)
		return p, nil
	}
	return Plan{}, last
}

// resourceDocument is the protected resource metadata Pons reads.
type resourceDocument struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// challengeMember reads one member of a WWW-Authenticate challenge.
var challengeMember = regexp.MustCompile(`(resource_metadata|scope)="([^"]*)"`)

// resourceMetadata finds and validates a connector's protected resource
// metadata, and answers the scopes its challenge named.
func (s *Signin) resourceMetadata(ctx context.Context, conn Connector) (resourceDocument, []string, error) {
	u, err := url.Parse(conn.URL)
	if err != nil {
		return resourceDocument{}, nil, unsupported("url")
	}
	var addresses []string
	var scopes []string
	if challenge, ok, err := s.challenge(ctx, conn); err != nil {
		return resourceDocument{}, nil, err
	} else if ok {
		for _, m := range challengeMember.FindAllStringSubmatch(challenge, -1) {
			switch m[1] {
			case "resource_metadata":
				addresses = append(addresses, m[2])
			case "scope":
				scopes = strings.Fields(m[2])
			}
		}
	}
	root := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
	if p := strings.TrimSuffix(u.EscapedPath(), "/"); p != "" {
		addresses = append(addresses, root+p)
	}
	addresses = append(addresses, root)
	for _, address := range addresses {
		answer, err := s.Dial.Fetch(ctx, address, conn.Ports())
		if err != nil {
			return resourceDocument{}, nil, unreachable(err)
		}
		if answer.Status != http.StatusOK {
			continue
		}
		var doc resourceDocument
		if err := json.Unmarshal(answer.Body, &doc); err != nil {
			return resourceDocument{}, nil, unsupported("resource_metadata")
		}
		if !sameResource(doc.Resource, u) {
			return resourceDocument{}, nil, unsupported("resource_mismatch")
		}
		// An authorization server the dialer's rules refuse before
		// resolving it is an address that cannot be reached, named by the
		// rule, as an issuer or an endpoint of the metadata is.
		for _, as := range doc.AuthorizationServers {
			if why := checkEndpoint(as); why != "" {
				return resourceDocument{}, nil, apierr.Fail(apierr.CodeConnectorUnreachable, why)
			}
		}
		return doc, scopes, nil
	}
	return resourceDocument{}, nil, unsupported("no_resource_metadata")
}

// challenge makes the one request of discovery with no credential: for a
// connector of kind mcp, the tools/list of the probe of
// specs/008-carrying-a-call.md, and for one of kind http, a GET of its url.
// It answers the challenge of a 401 that names its resource metadata, and
// ok false for any other answer.
func (s *Signin) challenge(ctx context.Context, conn Connector) (string, bool, error) {
	var (
		req *http.Request
		err error
	)
	if conn.Kind == catalog.KindMCP {
		req, err = mcp.ListTools(ctx, conn.URL)
	} else if req, err = http.NewRequestWithContext(ctx, http.MethodGet, conn.URL, nil); err == nil {
		req.Header.Set("Accept", "application/json")
	}
	if err != nil {
		return "", false, unsupported("url")
	}
	resp, err := s.Dial.Do(ctx, dial.Request{HTTP: req, Ports: conn.Ports(), Timeout: tokenTimeout, MaxBody: maxTokenAnswer})
	if err != nil {
		return "", false, unreachable(err)
	}
	if err := resp.Body.Close(); err != nil {
		return "", false, unreachable(err)
	}
	for _, ch := range resp.Header.Values("WWW-Authenticate") {
		if resp.StatusCode == http.StatusUnauthorized && strings.Contains(ch, "resource_metadata=") {
			return ch, true, nil
		}
	}
	return "", false, nil
}

// sameResource reports whether a document's resource is the connector's:
// its scheme, host and port, and a path that is a prefix of the url's at a
// segment boundary.
func sameResource(resource string, u *url.URL) bool {
	r, err := url.Parse(resource)
	if err != nil || r.Scheme != u.Scheme || !strings.EqualFold(r.Host, u.Host) {
		return false
	}
	rp, up := strings.TrimSuffix(r.Path, "/"), strings.TrimSuffix(u.Path, "/")
	return rp == "" || up == rp || strings.HasPrefix(up, rp+"/")
}

// metadataDocument is the authorization server metadata Pons reads.
type metadataDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	IssParameterSupported             bool     `json:"authorization_response_iss_parameter_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
}

// metadataAddresses are where an issuer's metadata is looked for, in the
// protocol's order (RFC 8414 and OpenID Connect Discovery).
func metadataAddresses(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, errors.New("signin: an issuer that is not a URL")
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	if path == "" {
		return []string{origin + "/.well-known/oauth-authorization-server", origin + "/.well-known/openid-configuration"}, nil
	}
	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + "/.well-known/openid-configuration" + path,
		origin + path + "/.well-known/openid-configuration",
	}, nil
}

// metadata fetches and validates an issuer's metadata before any of it is
// used: its issuer is the one the address was built from, both endpoints
// are present and https on a name the host rule admits, and it supports
// the proof key's S256.
func (s *Signin) metadata(ctx context.Context, conn Connector, issuer string) (metadataDocument, error) {
	if why := checkEndpoint(issuer); why != "" {
		return metadataDocument{}, apierr.Fail(apierr.CodeConnectorUnreachable, why)
	}
	addresses, err := metadataAddresses(issuer)
	if err != nil {
		return metadataDocument{}, unsupported("issuer")
	}
	for _, address := range addresses {
		answer, err := s.Dial.Fetch(ctx, address, conn.Ports())
		if err != nil {
			return metadataDocument{}, unreachable(err)
		}
		if answer.Status != http.StatusOK {
			continue
		}
		var md metadataDocument
		if err := json.Unmarshal(answer.Body, &md); err != nil {
			return metadataDocument{}, unsupported("metadata")
		}
		switch {
		case md.Issuer != issuer:
			return metadataDocument{}, unsupported("issuer_mismatch")
		case md.AuthorizationEndpoint == "" || md.TokenEndpoint == "":
			return metadataDocument{}, unsupported("endpoints")
		case !slices.Contains(md.CodeChallengeMethodsSupported, "S256"):
			return metadataDocument{}, unsupported("no_s256")
		}
		for _, endpoint := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.RevocationEndpoint, md.RegistrationEndpoint} {
			if endpoint == "" {
				continue
			}
			if why := checkEndpoint(endpoint); why != "" {
				return metadataDocument{}, apierr.Fail(apierr.CodeConnectorUnreachable, why)
			}
		}
		return md, nil
	}
	return metadataDocument{}, unsupported("no_metadata")
}

// checkEndpoint holds an address a document names to the dialer's rules
// that need no network: https, no user part, a host the host rule admits.
// It answers the rule's name, or "".
func checkEndpoint(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Scheme != "https" || u.User != nil:
		return dial.SchemeNotHTTPS
	case catalog.CheckHost(u.Hostname()) != nil:
		return dial.HostNotAName
	}
	return ""
}

// planAt chooses how Pons identifies itself at an authorization server, in
// the protocol's order: the catalog's client, when the issuer is the one
// the entry names; a client metadata document; dynamic registration; or
// none, which is sign_in_unsupported.
func (s *Signin) planAt(ctx context.Context, conn Connector, md metadataDocument) (Plan, error) {
	p := Plan{
		Issuer: md.Issuer, AuthorizationEndpoint: md.AuthorizationEndpoint, TokenEndpoint: md.TokenEndpoint,
		RevocationEndpoint: md.RevocationEndpoint, IssParameterSupported: md.IssParameterSupported,
	}
	switch {
	case conn.Auth.Client != nil:
		if conn.Auth.Issuer != md.Issuer {
			// A client is bound to the server that issued it.
			return Plan{}, unsupported("client_at_another_issuer")
		}
		p.ClientID = conn.Auth.Client.ID
	case md.ClientIDMetadataDocumentSupported && strings.HasPrefix(s.PublicURL, "https://"):
		id := ""
		if conn.AddedURL != "" {
			id = conn.Ref
		}
		p.ClientID = s.ClientDocumentURL(id)
	case md.RegistrationEndpoint != "" && conn.AddedURL == "":
		id, err := s.register(ctx, conn, md)
		if err != nil {
			return Plan{}, err
		}
		p.ClientID = id
	default:
		return Plan{}, unsupported("no_client")
	}
	return p, nil
}

// scopes is the selection of specs/007-sign-in.md: the base, the scopes
// the request names, and offline_access when the server lists it.
func (s *Signin) scopes(base, requested []string, md metadataDocument) []string {
	out := union(base, requested)
	if slices.Contains(md.ScopesSupported, "offline_access") {
		out = union(out, []string{"offline_access"})
	}
	return out
}

// union is a followed by the members of b it lacks, in order.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
