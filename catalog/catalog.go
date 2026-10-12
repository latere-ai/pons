// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// The kinds of a connector: what its address speaks.
const (
	KindMCP  = "mcp"
	KindHTTP = "http"
)

// The ways a person gives access.
const (
	AuthOAuth             = "oauth"
	AuthToken             = "token"
	AuthClientCredentials = "client_credentials"
	AuthNone              = "none"
)

// The ways the authorization server of an oauth connector is found.
const (
	DiscoveryResource = "resource"
	DiscoveryIssuer   = "issuer"
	DiscoveryNone     = "none"
)

// The bounds of the members a person reads.
const (
	MaxNameLength        = 40
	MaxTitleLength       = 60
	MaxDescriptionLength = 200
	MaxHintLength        = 200
)

// The defaults of a token connector's inject.
const (
	DefaultInjectHeader = "Authorization"
	DefaultInjectFormat = "Bearer {value}"
	// Placeholder is where a key goes in an inject format.
	Placeholder = "{value}"
)

// Example is catalog/example.yaml: one connector per way to give access,
// for invented services.
//
//go:embed example.yaml
var Example []byte

// Catalog is the connectors an installation offers, in the order of its
// file.
type Catalog struct {
	Connectors []Connector `yaml:"connectors"`
}

// Get finds a connector by its name.
func (c Catalog) Get(name string) (Connector, bool) {
	for _, conn := range c.Connectors {
		if conn.Name == name {
			return conn, true
		}
	}
	return Connector{}, false
}

// Connector is what a service is: an entry of the catalog, or a connector
// a person added by its address (specs/002-objects.md).
type Connector struct {
	Name        string   `yaml:"name" json:"name"`
	Title       string   `yaml:"title" json:"title"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Icon        string   `yaml:"icon,omitempty" json:"icon,omitempty"`
	Kind        string   `yaml:"kind" json:"kind"`
	URL         string   `yaml:"url" json:"url"`
	Hosts       []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Auth        Auth     `yaml:"auth" json:"auth"`
	Tools       Marks    `yaml:"tools,omitempty" json:"tools"`
	Links       Links    `yaml:"links,omitempty" json:"links"`
}

// Auth is how a person gives access, with the members of its type.
type Auth struct {
	Type string `yaml:"type" json:"type"`

	// oauth
	Discovery    string   `yaml:"discovery,omitempty" json:"discovery,omitempty"`
	Issuer       string   `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	AuthorizeURL string   `yaml:"authorize_url,omitempty" json:"authorize_url,omitempty"`
	RevokeURL    string   `yaml:"revoke_url,omitempty" json:"revoke_url,omitempty"`
	Client       *Client  `yaml:"client,omitempty" json:"client,omitempty"`
	Resource     *bool    `yaml:"resource,omitempty" json:"resource,omitempty"`
	Account      *Account `yaml:"account,omitempty" json:"account,omitempty"`

	// oauth and client_credentials
	TokenURL string   `yaml:"token_url,omitempty" json:"token_url,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// client_credentials
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`

	// token
	Inject *Inject `yaml:"inject,omitempty" json:"inject,omitempty"`
	Hint   string  `yaml:"hint,omitempty" json:"hint,omitempty"`
}

// Client is a client the operator registered with the service.
type Client struct {
	ID     string     `yaml:"id" json:"id"`
	Secret *SecretRef `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// Inject is where a key goes in a forwarded request: a header, valued by a
// format with Placeholder exactly once.
type Inject struct {
	Header string `yaml:"header,omitempty" json:"header"`
	Format string `yaml:"format,omitempty" json:"format"`
}

// Account is where the account a connection acts as is read once after a
// sign-in (specs/013-github-connector.md).
type Account struct {
	URL   string `yaml:"url" json:"url"`
	Field string `yaml:"field" json:"field"`
}

// Links are links a client may show beside a connection, which Pons never
// fetches.
type Links struct {
	Manage string `yaml:"manage,omitempty" json:"manage,omitempty"`
}

// ResourceFor is whether the requests of a sign-in name the server a token
// is for: the entry's resource, or true for kind mcp and false for http.
func (c Connector) ResourceFor() bool {
	if c.Auth.Resource != nil {
		return *c.Auth.Resource
	}
	return c.Kind == KindMCP
}

// HostPatterns are the hosts a credential of the connector may be sent
// to: its hosts, or the one host of its url when it lists none.
func (c Connector) HostPatterns() []string {
	if len(c.Hosts) > 0 {
		return c.Hosts
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil
	}
	return []string{Normalize(u.Hostname())}
}

// Ports are the ports beyond 443 the connector's addresses name: the port
// of its url and of an address its auth members name.
func (c Connector) Ports() []int {
	var out []int
	for _, raw := range []string{c.URL, c.Auth.Issuer, c.Auth.AuthorizeURL, c.Auth.TokenURL, c.Auth.RevokeURL, accountURL(c.Auth.Account)} {
		if p := portOf(raw); p != 0 && p != 443 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func accountURL(a *Account) string {
	if a == nil {
		return ""
	}
	return a.URL
}

// InjectOrDefault is the inject of a token connector with its defaults.
func (c Connector) InjectOrDefault() Inject {
	in := Inject{Header: DefaultInjectHeader, Format: DefaultInjectFormat}
	if c.Auth.Inject != nil {
		if c.Auth.Inject.Header != "" {
			in.Header = c.Auth.Inject.Header
		}
		if c.Auth.Inject.Format != "" {
			in.Format = c.Auth.Inject.Format
		}
	}
	return in
}

// Problem is one thing wrong with a connector: the member, as a dotted
// path, and why.
type Problem struct {
	Field string
	Why   string
}

func (p Problem) Error() string { return p.Field + ": " + p.Why }

// Options configure Load.
type Options struct {
	// LookupEnv resolves an {env: NAME} reference. Nil resolves none: every
	// such reference is one that does not resolve.
	LookupEnv func(string) (string, bool)
}

// LoadError is a catalog that does not load: one line per problem, each
// naming the entry and the member.
type LoadError struct {
	Lines []string
}

func (e *LoadError) Error() string { return strings.Join(e.Lines, "\n") }

// Load reads a catalog file and validates all of it. Every reference to a
// secret is resolved once, to prove it resolves, and the value is dropped.
func Load(path string, o Options) (Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, fmt.Errorf("catalog: %w", err)
	}
	return Parse(b, o)
}

// Parse validates a catalog document, as Load does for a file.
func Parse(doc []byte, o Options) (Catalog, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return Catalog{}, &LoadError{Lines: []string{"catalog: the file is not YAML: " + err.Error()}}
	}
	fail := &LoadError{}
	add := func(entry string, ps ...Problem) {
		for _, p := range ps {
			fail.Lines = append(fail.Lines, "catalog: "+entry+p.Error())
		}
	}
	var c Catalog
	if len(root.Content) == 0 {
		return c, nil // an empty file is an empty catalog
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return Catalog{}, &LoadError{Lines: []string{"catalog: the file is not a mapping with the key connectors"}}
	}
	add("", keys(top, "", "connectors")...)
	list := member(top, "connectors")
	if list != nil && list.Kind != yaml.SequenceNode {
		add("", Problem{"connectors", "is not a list"})
		return Catalog{}, fail
	}
	if list != nil {
		for i, node := range list.Content {
			entry := fmt.Sprintf("connectors[%d]", i)
			if name := member(node, "name"); name != nil && name.Kind == yaml.ScalarNode {
				entry += fmt.Sprintf(" %q", name.Value)
			}
			entry += ": "
			if ps := structure(node); len(ps) > 0 {
				add(entry, ps...)
				continue
			}
			var conn Connector
			if err := node.Decode(&conn); err != nil {
				add(entry, Problem{"entry", "does not read: " + err.Error()})
				continue
			}
			ps := Validate(conn, false)
			ps = append(ps, resolve(conn, o)...)
			if slices.ContainsFunc(c.Connectors, func(other Connector) bool { return other.Name == conn.Name }) && conn.Name != "" {
				ps = append(ps, Problem{"name", "is used by an earlier entry"})
			}
			add(entry, ps...)
			c.Connectors = append(c.Connectors, conn)
		}
	}
	if len(fail.Lines) > 0 {
		return Catalog{}, fail
	}
	return c, nil
}

// The members each level of an entry takes. An auth takes type and the
// members of that type alone.
var (
	connectorKeys = []string{"name", "title", "description", "icon", "kind", "url", "hosts", "auth", "tools", "links"}
	authKeys      = map[string][]string{
		AuthOAuth:             {"type", "discovery", "issuer", "authorize_url", "token_url", "revoke_url", "client", "scopes", "resource", "account"},
		AuthToken:             {"type", "inject", "hint"},
		AuthClientCredentials: {"type", "token_url", "scopes", "audience"},
		AuthNone:              {"type"},
	}
	clientKeys  = []string{"id", "secret"}
	secretKeys  = []string{"env", "file"}
	injectKeys  = []string{"header", "format"}
	accountKeys = []string{"url", "field"}
	toolsKeys   = []string{"read_only", "hidden"}
	linksKeys   = []string{"manage"}
)

// structure checks the keys of an entry at every level before it is
// decoded, so a key the format does not describe is named where it is.
func structure(node *yaml.Node) []Problem {
	if node.Kind != yaml.MappingNode {
		return []Problem{{"entry", "is not a mapping"}}
	}
	ps := keys(node, "", connectorKeys...)
	if auth := member(node, "auth"); auth != nil {
		if auth.Kind != yaml.MappingNode {
			return append(ps, Problem{"auth", "is not a mapping"})
		}
		typ := member(auth, "type")
		allowed, ok := []string(nil), false
		if typ != nil {
			allowed, ok = authKeys[typ.Value]
		}
		if ok {
			ps = append(ps, keys(auth, "auth.", allowed...)...)
		}
		if client := member(auth, "client"); client != nil {
			ps = append(ps, keys(client, "auth.client.", clientKeys...)...)
			if secret := member(client, "secret"); secret != nil {
				if secret.Kind != yaml.MappingNode {
					ps = append(ps, Problem{"auth.client.secret", "write a reference, {env: NAME} or {file: /path}, not a value"})
				} else {
					ps = append(ps, keys(secret, "auth.client.secret.", secretKeys...)...)
				}
			}
		}
		for _, nested := range []struct {
			name string
			keys []string
		}{{"inject", injectKeys}, {"account", accountKeys}} {
			if n := member(auth, nested.name); n != nil {
				ps = append(ps, keys(n, "auth."+nested.name+".", nested.keys...)...)
			}
		}
	}
	if tools := member(node, "tools"); tools != nil {
		ps = append(ps, keys(tools, "tools.", toolsKeys...)...)
	}
	if links := member(node, "links"); links != nil {
		ps = append(ps, keys(links, "links.", linksKeys...)...)
	}
	return ps
}

// keys names every key of a mapping that is not allowed.
func keys(node *yaml.Node, prefix string, allowed ...string) []Problem {
	if node.Kind != yaml.MappingNode {
		return []Problem{{strings.TrimSuffix(prefix, "."), "is not a mapping"}}
	}
	var ps []Problem
	for i := 0; i+1 < len(node.Content); i += 2 {
		if k := node.Content[i].Value; !slices.Contains(allowed, k) {
			ps = append(ps, Problem{prefix + k, "is not a member the format describes here"})
		}
	}
	return ps
}

// member is the value of one key of a mapping, or nil.
func member(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// resolve proves every reference of an entry resolves, and drops the
// values.
func resolve(c Connector, o Options) []Problem {
	if c.Auth.Client == nil || c.Auth.Client.Secret == nil {
		return nil
	}
	if _, err := c.Auth.Client.Secret.Resolve(o.LookupEnv); err != nil {
		return []Problem{{"auth.client.secret", err.Error()}}
	}
	return nil
}

// Validate checks one connector against the rules of specs/006-catalog.md.
// added holds it to the rules of a connector a person adds by its address.
// The problems name the member as a dotted path.
func Validate(c Connector, added bool) []Problem {
	var ps []Problem
	bad := func(field, why string) { ps = append(ps, Problem{field, why}) }

	if !IsLabel(c.Name) {
		bad("name", fmt.Sprintf("is not a DNS label of at most %d characters", MaxNameLength))
	}
	if c.Title == "" || utf8.RuneCountInString(c.Title) > MaxTitleLength {
		bad("title", fmt.Sprintf("is empty or longer than %d characters", MaxTitleLength))
	}
	if utf8.RuneCountInString(c.Description) > MaxDescriptionLength {
		bad("description", fmt.Sprintf("is longer than %d characters", MaxDescriptionLength))
	}
	if c.Icon != "" {
		if why := checkHTTPS(c.Icon, false); why != "" {
			bad("icon", why)
		}
	}
	switch {
	case c.Kind != KindMCP && c.Kind != KindHTTP:
		bad("kind", "is not mcp or http")
	case added && c.Kind != KindMCP:
		bad("kind", "is not mcp: a connector of kind http comes from the catalog alone")
	}
	urlHost := ""
	if why := checkHTTPS(c.URL, added); why != "" {
		bad("url", why)
	} else if u, err := url.Parse(c.URL); err == nil {
		urlHost = Normalize(u.Hostname())
	}
	switch {
	case added && len(c.Hosts) > 0:
		bad("hosts", "is not taken for a connector a person adds: its credential goes to the host of its url alone")
	case len(c.Hosts) > 0:
		for i, h := range c.Hosts {
			if CheckPattern(h) != nil {
				bad(fmt.Sprintf("hosts[%d]", i), "is not a host pattern: a name of two labels or more, or *. before one, and no address or private name")
			}
		}
		if urlHost != "" && !Matcher(c.Hosts).Matches(urlHost) {
			bad("hosts", "does not cover the host of url")
		}
	}
	ps = append(ps, validateAuth(c, added)...)
	for field, globs := range map[string][]string{"tools.read_only": c.Tools.ReadOnly, "tools.hidden": c.Tools.Hidden} {
		if slices.Contains(globs, "") {
			bad(field, "has an empty glob")
		}
	}
	if c.Links.Manage != "" {
		switch {
		case added:
			bad("links", "is not taken for a connector a person adds")
		default:
			if why := checkHTTPS(c.Links.Manage, false); why != "" {
				bad("links.manage", why)
			}
		}
	}
	slices.SortStableFunc(ps, func(a, b Problem) int { return strings.Compare(a.Field, b.Field) })
	return ps
}

// validateAuth checks auth and the members of its type.
func validateAuth(c Connector, added bool) []Problem {
	var ps []Problem
	bad := func(field, why string) { ps = append(ps, Problem{field, why}) }
	a := c.Auth
	endpoint := func(field, raw string) {
		if why := checkHTTPS(raw, added); why != "" {
			bad(field, why)
		}
	}
	// What another type takes is refused, so a member of the wrong type is
	// never silently ignored.
	other := func(field string, set bool) {
		if set {
			bad("auth."+field, "is not a member of auth.type "+a.Type)
		}
	}

	switch a.Type {
	case AuthOAuth:
		if added {
			if a.Discovery != "" && a.Discovery != DiscoveryResource {
				bad("auth.discovery", "is resource for a connector a person adds")
			}
			other("issuer", a.Issuer != "")
			other("authorize_url", a.AuthorizeURL != "")
			other("token_url", a.TokenURL != "")
			other("revoke_url", a.RevokeURL != "")
			other("client", a.Client != nil)
			other("resource", a.Resource != nil)
			other("account", a.Account != nil)
			break
		}
		discovery := a.Discovery
		if discovery == "" && c.Kind == KindMCP {
			discovery = DiscoveryResource
		}
		switch discovery {
		case DiscoveryResource, DiscoveryIssuer, DiscoveryNone:
		case "":
			bad("auth.discovery", "is required for kind http: resource, issuer or none")
		default:
			bad("auth.discovery", "is not resource, issuer or none")
		}
		if a.Issuer != "" {
			endpoint("auth.issuer", a.Issuer)
		}
		switch {
		case discovery == DiscoveryIssuer && a.Issuer == "":
			bad("auth.issuer", "is required with discovery issuer")
		case discovery == DiscoveryResource && a.Client != nil && a.Issuer == "":
			bad("auth.issuer", "is required with a client, to name the server that client is registered with")
		}
		if discovery == DiscoveryNone {
			if a.AuthorizeURL == "" || a.TokenURL == "" {
				bad("auth", "takes authorize_url and token_url with discovery none")
			}
			if a.Client == nil {
				bad("auth.client", "is required with discovery none")
			}
		} else {
			other("authorize_url", a.AuthorizeURL != "")
			other("token_url", a.TokenURL != "")
			other("revoke_url", a.RevokeURL != "")
		}
		for field, raw := range map[string]string{"auth.authorize_url": a.AuthorizeURL, "auth.token_url": a.TokenURL, "auth.revoke_url": a.RevokeURL} {
			if raw != "" {
				endpoint(field, raw)
			}
		}
		if a.Client != nil {
			if a.Client.ID == "" {
				bad("auth.client.id", "is required")
			}
			if s := a.Client.Secret; s != nil && (s.Env == "") == (s.File == "") {
				bad("auth.client.secret", "names exactly one of env and file")
			}
		}
		if a.Account != nil {
			if why := checkHTTPS(a.Account.URL, false); why != "" {
				bad("auth.account.url", why)
			} else if u, err := url.Parse(a.Account.URL); err == nil && !Matcher(c.HostPatterns()).Matches(Normalize(u.Hostname())) {
				bad("auth.account.url", "is on a host hosts does not cover, so the token would go where a call would not take it")
			}
			if a.Account.Field == "" {
				bad("auth.account.field", "is required")
			}
		}
		other("inject", a.Inject != nil)
		other("hint", a.Hint != "")
		other("audience", a.Audience != "")
	case AuthToken:
		if a.Inject != nil {
			in := c.InjectOrDefault()
			if !injectable(in.Header) {
				bad("auth.inject.header", "is not a header name the carrier leaves to the connector's credential")
			}
			if strings.Count(in.Format, Placeholder) != 1 || !visible(in.Format) {
				bad("auth.inject.format", "holds {value} exactly once and visible ASCII and spaces only")
			}
		}
		if utf8.RuneCountInString(a.Hint) > MaxHintLength {
			bad("auth.hint", fmt.Sprintf("is longer than %d characters", MaxHintLength))
		}
		otherThan(a, AuthToken, other)
	case AuthClientCredentials:
		if added {
			bad("auth.type", "is oauth, token or none for a connector a person adds")
			break
		}
		if a.TokenURL == "" {
			bad("auth.token_url", "is required")
		} else {
			endpoint("auth.token_url", a.TokenURL)
		}
		otherThan(a, AuthClientCredentials, other)
	case AuthNone:
		otherThan(a, AuthNone, other)
	default:
		bad("auth.type", "is not oauth, token, client_credentials or none")
	}
	if slices.Contains(a.Scopes, "") {
		bad("auth.scopes", "has an empty scope")
	}
	return ps
}

// otherThan refuses the members of oauth on a connector of another type,
// and those of the other two types it does not take.
func otherThan(a Auth, typ string, other func(string, bool)) {
	other("discovery", a.Discovery != "")
	other("issuer", a.Issuer != "")
	other("authorize_url", a.AuthorizeURL != "")
	other("revoke_url", a.RevokeURL != "")
	other("client", a.Client != nil)
	other("resource", a.Resource != nil)
	other("account", a.Account != nil)
	if typ != AuthClientCredentials {
		other("token_url", a.TokenURL != "")
		other("audience", a.Audience != "")
		if typ != AuthOAuth {
			other("scopes", len(a.Scopes) > 0)
		}
	}
	if typ != AuthToken {
		other("inject", a.Inject != nil)
		other("hint", a.Hint != "")
	}
}

// checkHTTPS checks an address a connector names: https, a host that passes
// the host rule, no user part and no fragment; on port 443 alone for a
// connector a person adds. It answers why not, or "".
func checkHTTPS(raw string, only443 bool) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || raw == "":
		return "is not a URL"
	case u.Scheme != "https":
		return "is not https"
	case u.User != nil:
		return "carries a user part"
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return "carries a fragment"
	case CheckHost(u.Hostname()) != nil:
		return "has a host that is an address, a single label or a private name"
	case portOf(raw) < 0:
		return "has a port that is not a number"
	case only443 && portOf(raw) != 0 && portOf(raw) != 443:
		return "is not on port 443"
	}
	return ""
}

// portOf is the explicit port of a URL: 0 for none, -1 for one that is not
// a number from 1 to 65535.
func portOf(raw string) int {
	u, err := url.Parse(raw)
	if err != nil || u.Port() == "" {
		return 0
	}
	n := 0
	for _, r := range u.Port() {
		if r < '0' || r > '9' || n > 65535 {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	if n < 1 || n > 65535 {
		return -1
	}
	return n
}

// IsLabel reports whether s is a DNS label of at most MaxNameLength
// characters: lowercase letters, digits and hyphens, neither starting nor
// ending with a hyphen. A label holds no underscore, and the id of an added
// connector always does, so the two never collide.
func IsLabel(s string) bool {
	if s == "" || len(s) > MaxNameLength || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// carrierHeaders are the headers the carrier sets, removes or passes
// itself (specs/008-carrying-a-call.md), which a key may not be placed in.
var carrierHeaders = []string{
	"accept", "content-type", "content-length", "host", "user-agent", "cookie", "origin",
	"mcp-protocol-version", "mcp-method", "mcp-name", "mcp-session-id", "last-event-id",
	"forwarded", "x-real-ip", "via", "connection", "keep-alive", "proxy-authorization",
	"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}

// injectable reports whether a header name may carry a key: a token of
// RFC 9110 that the carrier does not itself set, remove or pass.
func injectable(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}
	lower := strings.ToLower(name)
	return !slices.Contains(carrierHeaders, lower) &&
		!strings.HasPrefix(lower, "x-forwarded-") && !strings.HasPrefix(lower, "mcp-param-")
}

// visible reports whether s holds visible ASCII and spaces only.
func visible(s string) bool {
	for i := range len(s) {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// SecretRef names a secret without writing it: exactly one of a variable
// and the absolute path of a file.
type SecretRef struct {
	Env  string `yaml:"env,omitempty" json:"env,omitempty"`
	File string `yaml:"file,omitempty" json:"file,omitempty"`
}

// ErrUnresolved is a reference that does not resolve.
var ErrUnresolved = errors.New("the reference does not resolve")

// Resolve reads the secret, at each use, with one trailing newline
// removed, so a file can be rotated in place. lookupEnv resolves a
// variable; the error names neither the value nor the file's content.
func (r SecretRef) Resolve(lookupEnv func(string) (string, bool)) (string, error) {
	switch {
	case r.Env != "" && r.File == "":
		if lookupEnv == nil {
			return "", fmt.Errorf("%w: the variable %s is not set", ErrUnresolved, r.Env)
		}
		v, ok := lookupEnv(r.Env)
		if !ok || v == "" {
			return "", fmt.Errorf("%w: the variable %s is not set", ErrUnresolved, r.Env)
		}
		return trimNewline(v), nil
	case r.File != "" && r.Env == "":
		if !filepath.IsAbs(r.File) {
			return "", fmt.Errorf("%w: the file is not an absolute path", ErrUnresolved)
		}
		b, err := os.ReadFile(r.File)
		if err != nil {
			return "", fmt.Errorf("%w: the file cannot be read", ErrUnresolved)
		}
		if v := trimNewline(string(b)); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%w: the file is empty", ErrUnresolved)
	}
	return "", fmt.Errorf("%w: it names exactly one of env and file", ErrUnresolved)
}

func trimNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
