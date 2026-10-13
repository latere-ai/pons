// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pons/catalog"
)

// env resolves the example file's one reference.
func env(name string) (string, bool) {
	if name == "TRACKER_CLIENT_SECRET" {
		return "tracker-client-secret\n", true
	}
	return "", false
}

func load(t *testing.T, doc string) (catalog.Catalog, error) {
	t.Helper()
	return catalog.Parse([]byte(doc), catalog.Options{LookupEnv: env})
}

// The example file loads with one entry per auth.type, and each type takes
// its own members with their defaults.
func TestExampleFileLoads(t *testing.T) {
	c, err := catalog.Load(filepath.Join(".", "example.yaml"), catalog.Options{LookupEnv: env})
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, conn := range c.Connectors {
		types = append(types, conn.Auth.Type)
	}
	if !slices.Equal(types, []string{"oauth", "token", "client_credentials", "none"}) {
		t.Fatalf("types %v", types)
	}
	if string(catalog.Example) == "" {
		t.Fatal("the example is not embedded")
	}
	tracker, ok := c.Get("tracker")
	if !ok || !tracker.ResourceFor() || tracker.Auth.Client.ID != "pons" {
		t.Fatalf("tracker %+v", tracker)
	}
	search, _ := c.Get("search")
	if in := search.InjectOrDefault(); in.Header != "X-Api-Key" || in.Format != "{value}" {
		t.Fatalf("search inject %+v", in)
	}
	if got := search.HostPatterns(); !slices.Equal(got, []string{"api.search.example.net"}) {
		t.Fatalf("absent hosts are the host of url: %v", got)
	}
	weather, _ := c.Get("weather")
	if in := weather.InjectOrDefault(); in.Header != "Authorization" || in.Format != "Bearer {value}" {
		t.Fatalf("the default inject %+v", in)
	}
	if _, ok := c.Get("nothing"); ok {
		t.Fatal("a name the file lacks is found")
	}
	if c, err := catalog.Parse(nil, catalog.Options{}); err != nil || len(c.Connectors) != 0 {
		t.Fatalf("an empty file: %+v %v", c, err)
	}
	if _, err := catalog.Load(filepath.Join(t.TempDir(), "none.yaml"), catalog.Options{}); err == nil {
		t.Fatal("a missing file loads")
	}
}

// Each type takes its own members with their defaults and refuses another
// type's.
func TestAuthMembers(t *testing.T) {
	entry := func(auth string) string {
		return "connectors:\n  - name: one\n    title: One\n    kind: mcp\n    url: https://one.example.com/mcp\n    auth: " + auth + "\n"
	}
	good := []string{
		`{type: none}`,
		`{type: token}`,
		`{type: token, inject: {header: X-Key}, hint: Make one.}`,
		`{type: client_credentials, token_url: "https://login.example.com/token", scopes: [a], audience: x}`,
		`{type: oauth}`,
		`{type: oauth, discovery: resource, scopes: [read]}`,
		`{type: oauth, discovery: resource, issuer: "https://login.example.com", client: {id: c}}`,
		`{type: oauth, discovery: issuer, issuer: "https://login.example.com"}`,
		`{type: oauth, discovery: none, authorize_url: "https://login.example.com/a", token_url: "https://login.example.com/t", revoke_url: "https://login.example.com/r", client: {id: c, secret: {file: ` + secretFile(t) + `}}, resource: false}`,
	}
	for _, auth := range good {
		if _, err := load(t, entry(auth)); err != nil {
			t.Errorf("%s: %v", auth, err)
		}
	}
	bad := map[string]string{
		`{type: none, scopes: [a]}`:                                                 "auth.scopes",
		`{type: token, token_url: "https://login.example.com/t"}`:                   "auth.token_url",
		`{type: token, inject: {header: Cookie}}`:                                   "auth.inject.header",
		`{type: token, inject: {header: "X Key"}}`:                                  "auth.inject.header",
		`{type: token, inject: {header: Mcp-Param-Id}}`:                             "auth.inject.header",
		`{type: token, inject: {format: "{value}{value}"}}`:                         "auth.inject.format",
		`{type: token, inject: {format: "Bearer\t{value}"}}`:                        "auth.inject.format",
		`{type: token, hint: "` + strings.Repeat("h", 201) + `"}`:                   "auth.hint",
		`{type: client_credentials}`:                                                "auth.token_url",
		`{type: client_credentials, token_url: "http://login.example.com/t"}`:       "auth.token_url",
		`{type: client_credentials, token_url: "https://l.example.com/t", hint: x}`: "auth.hint",
		`{type: oauth, inject: {header: X}}`:                                        "auth.inject",
		`{type: oauth, discovery: issuer}`:                                          "auth.issuer",
		`{type: oauth, discovery: other}`:                                           "auth.discovery",
		`{type: oauth, client: {id: c}}`:                                            "auth.issuer",
		`{type: oauth, discovery: none, client: {id: c}}`:                           "auth:",
		`{type: oauth, discovery: none, authorize_url: "https://a.example.com/a", token_url: "https://a.example.com/t"}`:                             "auth.client",
		`{type: oauth, authorize_url: "https://a.example.com/a"}`:                                                                                    "auth.authorize_url",
		`{type: oauth, discovery: none, authorize_url: "http://a.example.com/a", token_url: "https://a.example.com/t", client: {id: c}}`:             "auth.authorize_url",
		`{type: oauth, discovery: issuer, issuer: "https://10.0.0.1"}`:                                                                               "auth.issuer",
		`{type: oauth, discovery: none, authorize_url: "https://a.example.com/a", token_url: "https://a.example.com/t", client: {secret: {env: X}}}`: "auth.client.id",
		`{type: oauth, scopes: [""]}`: "auth.scopes",
		`{type: other}`:               "auth.type",
		`{type: oauth, nonsense: 1}`:  "auth.nonsense",
		`[none]`:                      "auth: is not a mapping",
	}
	for auth, member := range bad {
		_, err := load(t, entry(auth))
		if err == nil || !strings.Contains(err.Error(), `connectors[0] "one": `+member) {
			t.Errorf("%s: want a problem with %s, got %v", auth, member, err)
		}
	}
	// The kind decides two defaults of oauth.
	http := "connectors:\n  - name: api\n    title: API\n    kind: http\n    url: https://api.example.com\n    auth: {type: oauth}\n"
	if _, err := load(t, http); err == nil || !strings.Contains(err.Error(), "auth.discovery") {
		t.Errorf("kind http with no discovery: %v", err)
	}
	c, err := load(t, strings.Replace(http, "{type: oauth}", "{type: oauth, discovery: issuer, issuer: \"https://login.example.com\"}", 1))
	if err != nil || c.Connectors[0].ResourceFor() {
		t.Errorf("kind http sends no resource by default: %v", err)
	}
}

func secretFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A file with an unknown key at any level, a duplicate name, a non-https
// url, an inline secret, an unresolved reference or a bad host pattern
// refuses the start, and each message names the entry and the member.
func TestLoadRefusals(t *testing.T) {
	const ok = "    title: One\n    kind: mcp\n    url: https://one.example.com/mcp\n    auth: {type: none}\n"
	cases := map[string]struct{ doc, want string }{
		"an unknown top-level key": {"version: 2\nconnectors: []\n", "catalog: version:"},
		"an unknown entry key":     {"connectors:\n  - name: one\n    colour: red\n" + ok, `connectors[0] "one": colour:`},
		"an unknown nested key":    {"connectors:\n  - name: one\n" + ok + "    tools: {read_only: [a], write: [b]}\n", `connectors[0] "one": tools.write:`},
		"an unknown links key":     {"connectors:\n  - name: one\n" + ok + "    links: {home: x}\n", `connectors[0] "one": links.home:`},
		"a duplicate name":         {"connectors:\n  - name: one\n" + ok + "  - name: one\n" + ok, `connectors[1] "one": name: is used by an earlier entry`},
		"a name not a label":       {"connectors:\n  - name: One_1\n" + ok, `name: is not a DNS label`},
		"a long name":              {"connectors:\n  - name: " + strings.Repeat("a", 41) + "\n" + ok, `name: is not a DNS label`},
		"http url": {"connectors:\n  - name: one\n    title: One\n    kind: mcp\n    url: http://one.example.com/mcp\n    auth: {type: none}\n",
			`url: is not https`},
		"an http icon": {"connectors:\n  - name: one\n    icon: http://one.example.com/i.svg\n" + ok, `icon: is not https`},
		"an inline secret": {"connectors:\n  - name: tracker\n    title: T\n    kind: mcp\n    url: https://t.example.com/mcp\n    auth:\n      type: oauth\n      discovery: issuer\n      issuer: https://login.example.com\n      client: {id: pons, secret: hunter2hunter2}\n",
			`catalog: connectors[0] "tracker": auth.client.secret: write a reference, {env: NAME} or {file: /path}, not a value`},
		"an unresolved reference": {"connectors:\n  - name: one\n    title: T\n    kind: mcp\n    url: https://t.example.com/mcp\n    auth:\n      type: oauth\n      discovery: issuer\n      issuer: https://login.example.com\n      client: {id: pons, secret: {env: MISSING}}\n",
			`auth.client.secret: the reference does not resolve: the variable MISSING is not set`},
		"two references": {"connectors:\n  - name: one\n    title: T\n    kind: mcp\n    url: https://t.example.com/mcp\n    auth:\n      type: oauth\n      discovery: issuer\n      issuer: https://login.example.com\n      client: {id: pons, secret: {env: A, file: /b}}\n",
			`auth.client.secret: names exactly one`},
		"an unknown secret key": {"connectors:\n  - name: one\n    title: T\n    kind: mcp\n    url: https://t.example.com/mcp\n    auth:\n      type: oauth\n      discovery: issuer\n      issuer: https://login.example.com\n      client: {id: pons, secret: {vault: x}}\n",
			`auth.client.secret.vault:`},
		"a bad host pattern":    {"connectors:\n  - name: one\n" + ok + "    hosts: [\"one.example.com\", \"localhost\"]\n", `hosts[1]: is not a host pattern`},
		"hosts that miss url":   {"connectors:\n  - name: one\n" + ok + "    hosts: [\"*.one.example.com\"]\n", `hosts: does not cover the host of url`},
		"an empty glob":         {"connectors:\n  - name: one\n" + ok + "    tools: {hidden: [\"\"]}\n", `tools.hidden: has an empty glob`},
		"an entry not a map":    {"connectors:\n  - one\n", `entry: is not a mapping`},
		"connectors not a list": {"connectors: {one: 1}\n", `connectors: is not a list`},
		"not a mapping":         {"- one\n", `not a mapping`},
		"not yaml":              {"connectors: [\n", `not YAML`},
		"a wrong type":          {"connectors:\n  - name: one\n    title: [x]\n    kind: mcp\n    url: https://one.example.com/mcp\n    auth: {type: none}\n", `entry: does not read`},
		"a bad kind":            {"connectors:\n  - name: one\n    title: One\n    kind: grpc\n    url: https://one.example.com/mcp\n    auth: {type: none}\n", `kind: is not mcp or http`},
		"no title":              {"connectors:\n  - name: one\n    kind: mcp\n    url: https://one.example.com/mcp\n    auth: {type: none}\n", `title: is empty`},
		"a long description":    {"connectors:\n  - name: one\n    description: " + strings.Repeat("d", 201) + "\n" + ok, `description: is longer`},
		"a manage link on http": {"connectors:\n  - name: one\n" + ok + "    links: {manage: \"http://one.example.com/m\"}\n", `links.manage: is not https`},
		"a sign-in member in authorize_url": {"connectors:\n  - name: one\n    title: T\n    kind: http\n    url: https://t.example.com\n    auth:\n      type: oauth\n      discovery: none\n      authorize_url: https://login.example.com/authorize?access_type=offline&client_id=other\n      token_url: https://login.example.com/token\n      client: {id: pons}\n",
			`auth.authorize_url: is not taken with client_id in its query, which the sign-in sets`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.doc)
			var le *catalog.LoadError
			if !errors.As(err, &le) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			for _, line := range le.Lines {
				if !strings.HasPrefix(line, "catalog: ") {
					t.Errorf("a line names no catalog: %q", line)
				}
			}
		})
	}
}

// A reference is read at each use: a file rewritten between two uses gives
// the new value without a restart.
func TestSecretRefIsReadAtUse(t *testing.T) {
	path := secretFile(t)
	ref := catalog.SecretRef{File: path}
	first, err := ref.Resolve(nil)
	if err != nil || first != "client-secret" {
		t.Fatalf("first %q %v", first, err)
	}
	if err := os.WriteFile(path, []byte("rotated-secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if second, err := ref.Resolve(nil); err != nil || second != "rotated-secret" {
		t.Fatalf("second %q %v", second, err)
	}
	if v, err := (catalog.SecretRef{Env: "TRACKER_CLIENT_SECRET"}).Resolve(env); err != nil || v != "tracker-client-secret" {
		t.Fatalf("env %q %v", v, err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []catalog.SecretRef{
		{}, {Env: "A", File: "/b"}, {Env: "TRACKER_CLIENT_SECRET"}, {Env: "MISSING"}, {File: "relative"},
		{File: filepath.Join(t.TempDir(), "none")}, {File: empty},
	} {
		lookup := env
		if bad.Env == "TRACKER_CLIENT_SECRET" {
			lookup = nil
		}
		if _, err := bad.Resolve(lookup); !errors.Is(err, catalog.ErrUnresolved) {
			t.Errorf("%+v resolved: %v", bad, err)
		}
	}
}

// A catalog name is a DNS label of at most 40 characters, and a reference
// resolves to a catalog name or to an id and never to both.
func TestNameRules(t *testing.T) {
	for _, s := range []string{"a", "github", "github-work", "a1", strings.Repeat("a", 40)} {
		if !catalog.IsLabel(s) {
			t.Errorf("%q is a label", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "A", "a_b", "a.b", strings.Repeat("a", 41), "ctr_01jb2m7c0p5d8f2h6j9k3m4n7q", "ü"} {
		if catalog.IsLabel(s) {
			t.Errorf("%q is not a label", s)
		}
	}
}

// An added connector is held to more than an entry.
func TestAddedConnectorValidation(t *testing.T) {
	base := catalog.Connector{Name: "wiki", Title: "Wiki", Kind: "mcp", URL: "https://wiki.example.com/mcp", Auth: catalog.Auth{Type: "oauth"}}
	if ps := catalog.Validate(base, true); len(ps) != 0 {
		t.Fatalf("a plain add: %v", ps)
	}
	yes := true
	cases := map[string]func(*catalog.Connector){
		"kind":               func(c *catalog.Connector) { c.Kind = "http" },
		"url":                func(c *catalog.Connector) { c.URL = "https://wiki.example.com:8443/mcp" },
		"hosts":              func(c *catalog.Connector) { c.Hosts = []string{"wiki.example.com"} },
		"auth.client":        func(c *catalog.Connector) { c.Auth.Client = &catalog.Client{ID: "x"} },
		"auth.issuer":        func(c *catalog.Connector) { c.Auth.Issuer = "https://login.example.com" },
		"auth.authorize_url": func(c *catalog.Connector) { c.Auth.AuthorizeURL = "https://login.example.com/a" },
		"auth.token_url":     func(c *catalog.Connector) { c.Auth.TokenURL = "https://login.example.com/t" },
		"auth.revoke_url":    func(c *catalog.Connector) { c.Auth.RevokeURL = "https://login.example.com/r" },
		"auth.resource":      func(c *catalog.Connector) { c.Auth.Resource = &yes },
		"auth.account": func(c *catalog.Connector) {
			c.Auth.Account = &catalog.Account{URL: "https://wiki.example.com/me", Field: "x"}
		},
		"auth.discovery": func(c *catalog.Connector) { c.Auth.Discovery = "none" },
		"auth.type": func(c *catalog.Connector) {
			c.Auth = catalog.Auth{Type: "client_credentials", TokenURL: "https://x.example.com/t"}
		},
		"links": func(c *catalog.Connector) { c.Links.Manage = "https://wiki.example.com/manage" },
	}
	for field, change := range cases {
		c := base
		c.Auth = base.Auth
		change(&c)
		ps := catalog.Validate(c, true)
		if !slices.ContainsFunc(ps, func(p catalog.Problem) bool { return p.Field == field }) {
			t.Errorf("%s: %v", field, ps)
		}
	}
	token := base
	token.Auth = catalog.Auth{Type: "token", Inject: &catalog.Inject{Header: "X-Api-Key", Format: "{value}"}, Hint: "Make a key."}
	if ps := catalog.Validate(token, true); len(ps) != 0 {
		t.Fatalf("a token add: %v", ps)
	}
	if got := (catalog.Problem{Field: "url", Why: "is not https"}).Error(); got != "url: is not https" {
		t.Fatalf("problem text %q", got)
	}
}

// auth.account and links.manage are refused when not https, and
// auth.account.url is refused when its host misses hosts.
func TestAccountAndLinksRules(t *testing.T) {
	entry := func(account, manage string) string {
		return "connectors:\n  - name: code\n    title: Code\n    kind: mcp\n    url: https://mcp.code.example.com/mcp\n" +
			"    hosts: [\"mcp.code.example.com\", \"api.code.example.com\"]\n" +
			"    auth:\n      type: oauth\n      discovery: none\n      authorize_url: https://code.example.com/authorize\n" +
			"      token_url: https://code.example.com/token\n      client: {id: c}\n      account: " + account + "\n" +
			"    links: {manage: \"" + manage + "\"}\n"
	}
	c, err := load(t, entry(`{url: "https://api.code.example.com/user", field: login}`, "https://code.example.com/apps/x/installations/new"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Connectors[0]; got.Auth.Account.Field != "login" || got.Links.Manage == "" {
		t.Fatalf("%+v", got)
	}
	for _, tc := range []struct{ account, manage, want string }{
		{`{url: "http://api.code.example.com/user", field: login}`, "https://code.example.com/m", "auth.account.url: is not https"},
		{`{url: "https://elsewhere.example.com/user", field: login}`, "https://code.example.com/m", "auth.account.url: is on a host"},
		{`{url: "https://api.code.example.com/user"}`, "https://code.example.com/m", "auth.account.field: is required"},
		{`{url: "https://api.code.example.com/user", field: login}`, "http://code.example.com/m", "links.manage: is not https"},
		{`{url: "https://api.code.example.com/user", field: login, method: POST}`, "https://code.example.com/m", "auth.account.method:"},
	} {
		if _, err := load(t, entry(tc.account, tc.manage)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: want %q, got %v", tc.account, tc.manage, tc.want, err)
		}
	}
}

// The ports beyond 443 an entry names.
func TestPorts(t *testing.T) {
	c := catalog.Connector{URL: "https://a.example.com:8443/mcp", Auth: catalog.Auth{
		TokenURL: "https://login.example.com:9443/t", Issuer: "https://login.example.com:9443",
		AuthorizeURL: "https://login.example.com/a", Account: &catalog.Account{URL: "https://a.example.com:443/me"},
	}}
	if got := c.Ports(); !slices.Equal(got, []int{8443, 9443}) {
		t.Fatalf("ports %v", got)
	}
	bad := catalog.Connector{Name: "x", Title: "X", Kind: "mcp", URL: "https://a.example.com:99999/mcp", Auth: catalog.Auth{Type: "none"}}
	if ps := catalog.Validate(bad, false); len(ps) == 0 {
		t.Fatal("a port past 65535 is accepted")
	}
	if got := (catalog.Connector{URL: "://"}).HostPatterns(); got != nil {
		t.Fatalf("a url that does not parse has hosts %v", got)
	}
}

// A problem names its rule in one word, the dialer's names for an address.
func TestProblemRules(t *testing.T) {
	cases := map[string]string{
		"https://wiki.example.com:8443/mcp": "port_not_allowed",
		"http://wiki.example.com/mcp":       "scheme_not_https",
		"https://u:p@wiki.example.com/mcp":  "scheme_not_https",
		"https://10.0.0.1/mcp":              "host_not_a_name",
		"https://wiki.example.com/mcp#x":    "fragment",
		"":                                  "not_a_url",
	}
	for u, want := range cases {
		c := catalog.Connector{Name: "w", Title: "W", Kind: "mcp", URL: u, Auth: catalog.Auth{Type: "none"}}
		ps := catalog.Validate(c, true)
		if len(ps) == 0 || ps[0].Rule() != want {
			t.Errorf("%q: %v", u, ps)
		}
	}
	for why, want := range map[string]string{"is not a DNS label of at most 40 characters": "not_a_dns_label", "something else": "invalid"} {
		if got := (catalog.Problem{Field: "f", Why: why}).Rule(); got != want {
			t.Errorf("%q: %s", why, got)
		}
	}
}
