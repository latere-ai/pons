// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pons/catalog"
)

// githubEntry is the YAML block under "### The entry" of spec 013, so the
// entry the spec shows is the entry the test loads.
func githubEntry(t *testing.T) string {
	t.Helper()
	return specYAML(t, ".archive/013-github-connector.md", "### The entry")
}

// specYAML is the first YAML block under heading in the spec file.
func specYAML(t *testing.T, file, heading string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "specs", file))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), heading+"\n")
	if !ok {
		t.Fatalf("%s has no section %q", file, heading)
	}
	_, block, ok := strings.Cut(after, "```yaml\n")
	if !ok {
		t.Fatalf("the section %q of %s has no yaml block", heading, file)
	}
	block, _, _ = strings.Cut(block, "```")
	return block
}

// The GitHub entry of spec 013 validates, with its git host, its headers and
// the two members a code host needs.
func TestTheGitHubEntry(t *testing.T) {
	c, err := catalog.Parse([]byte(githubEntry(t)), catalog.Options{LookupEnv: func(name string) (string, bool) {
		return "a-client-secret-of-the-test", name == "GITHUB_APP_CLIENT_SECRET"
	}})
	if err != nil {
		t.Fatal(err)
	}
	gh, ok := c.Get("github")
	if !ok {
		t.Fatal("no github entry")
	}
	if gh.Kind != catalog.KindHTTP || gh.GitURL() != "https://github.com" || gh.ResourceFor() {
		t.Fatalf("%+v", gh)
	}
	if in := gh.GitInjectOrDefault(); in.Scheme != catalog.GitBasic || in.Username != "x-access-token" {
		t.Fatalf("git inject %+v", in)
	}
	if !slices.Equal(gh.HTTP.Pass, []string{"X-GitHub-Api-Version"}) || len(gh.HTTP.PassBack) != 3 {
		t.Fatalf("http %+v", gh.HTTP)
	}
	if gh.Auth.Account == nil || gh.Auth.Account.Field != "login" || gh.Links.Manage == "" || gh.Auth.RevokeURL != "" {
		t.Fatalf("auth %+v links %+v", gh.Auth, gh.Links)
	}
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/repos/acme/app", catalog.EffectRead},
		{"HEAD", "/", catalog.EffectRead},
		{"OPTIONS", "/user", catalog.EffectRead},
		{"POST", "/graphql", catalog.EffectWrite},
		{"PATCH", "/repos/acme/app/issues/1", catalog.EffectWrite},
	} {
		if got := gh.RequestEffect(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s: %s", tc.method, tc.path, got)
		}
	}
}

// The Google entries of spec 015 validate: kind http with no resource
// member, the account read from a host under hosts, Google's revocation
// endpoint, which a disconnect asks only for a grant's last holder, the
// authorization request's members in authorize_url's query, each url as
// spec 015 names it, and Calendar's free time query reading while a draft
// writes.
func TestTheGoogleEntries(t *testing.T) {
	c, err := catalog.Parse([]byte(specYAML(t, "015-google-connectors.md", "### The entries")), catalog.Options{LookupEnv: func(name string) (string, bool) {
		return "a-client-secret-of-the-test", name == "GOOGLE_CLIENT_SECRET"
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Connectors) != 3 {
		t.Fatalf("%d entries", len(c.Connectors))
	}
	for _, name := range []string{"gmail", "google-calendar", "google-drive"} {
		g, ok := c.Get(name)
		if !ok {
			t.Fatalf("no %s entry", name)
		}
		a := g.Auth
		if g.Kind != catalog.KindHTTP || g.ResourceFor() || g.GitURL() != "" || a.Discovery != catalog.DiscoveryNone ||
			a.Issuer != "https://accounts.google.com" || a.RevokeURL != "https://oauth2.googleapis.com/revoke" || a.Client == nil || a.Client.Secret == nil || a.Client.Secret.Env != "GOOGLE_CLIENT_SECRET" {
			t.Fatalf("%s: %+v", name, g)
		}
		if a.Account == nil || a.Account.Field != "email" || !slices.Contains(g.HostPatterns(), "openidconnect.googleapis.com") {
			t.Fatalf("%s account %+v hosts %v", name, a.Account, g.HostPatterns())
		}
		if !slices.Contains(a.Scopes, "openid") || !slices.Contains(a.Scopes, "email") || len(a.Scopes) < 4 {
			t.Fatalf("%s scopes %v", name, a.Scopes)
		}
		u, err := url.Parse(a.AuthorizeURL)
		if err != nil || u.Query().Get("access_type") != "offline" || u.Query().Get("prompt") != "consent select_account" {
			t.Fatalf("%s authorize_url %q", name, a.AuthorizeURL)
		}
	}
	// Gmail's and Calendar's url is the product's versioned base; Drive's
	// is Google's host, since a file's content goes to the upload address
	// beside Drive's base (spec 015).
	for name, base := range map[string]string{
		"gmail": "https://gmail.googleapis.com/gmail/v1", "google-calendar": "https://www.googleapis.com/calendar/v3", "google-drive": "https://www.googleapis.com",
	} {
		if g, _ := c.Get(name); g.URL != base {
			t.Errorf("%s's url is %q, want %q", name, g.URL, base)
		}
	}
	cal, _ := c.Get("google-calendar")
	gmail, _ := c.Get("gmail")
	for _, tc := range []struct {
		conn               catalog.Connector
		method, path, want string
	}{
		{cal, "POST", "/freeBusy", catalog.EffectRead},
		{cal, "GET", "/calendars/primary/events", catalog.EffectRead},
		{cal, "POST", "/calendars/primary/events", catalog.EffectWrite},
		{gmail, "POST", "/users/me/drafts", catalog.EffectWrite},
		{gmail, "POST", "/users/me/messages/send", catalog.EffectWrite},
	} {
		if got := tc.conn.RequestEffect(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s %s: %s", tc.conn.Name, tc.method, tc.path, got)
		}
	}
}

// The members of kind http: each is refused where its rule says, the git
// host must be under hosts, and a read-only pattern makes a request read.
func TestHTTPMembers(t *testing.T) {
	entry := func(kind, extra string) string {
		return "connectors:\n  - name: api\n    title: API\n    kind: " + kind + "\n    url: https://api.example.com\n" +
			"    hosts: [\"api.example.com\", \"git.example.com\"]\n    auth: {type: token}\n" + extra
	}
	good := "    git: {url: \"https://git.example.com:8443\", inject: {scheme: bearer}}\n" +
		"    http: {read_only: [\"POST /search/*\"], pass: [X-Api-Version], pass_back: [\"X-RateLimit-*\"]}\n"
	c, err := load(t, entry("http", good))
	if err != nil {
		t.Fatal(err)
	}
	api := c.Connectors[0]
	if api.RequestEffect("POST", "/search/issues") != catalog.EffectRead || api.RequestEffect("POST", "/issues") != catalog.EffectWrite {
		t.Fatal("read_only does not decide the effect")
	}
	if got := api.Ports(); !slices.Equal(got, []int{8443}) {
		t.Fatalf("the git host's port is not named: %v", got)
	}
	if in := (catalog.Connector{}).GitInjectOrDefault(); in.Scheme != catalog.GitBearer {
		t.Fatalf("the default git inject %+v", in)
	}
	bad := map[string]string{
		"    git: {url: \"https://git.example.com\"}\n":                                         "kind mcp|git: is not taken",
		"    http: {pass: [X-A]}\n":                                                             "kind mcp|http: is not taken",
		"    git: {url: \"http://git.example.com\"}\n":                                          "http|git.url: is not https",
		"    git: {url: \"https://elsewhere.example.com\"}\n":                                   "http|git.url: is on a host",
		"    git: {url: \"https://git.example.com\", inject: {scheme: digest}}\n":               "http|git.inject.scheme",
		"    git: {url: \"https://git.example.com\", inject: {scheme: basic}}\n":                "http|git.inject.username",
		"    git: {url: \"https://git.example.com\", inject: {scheme: basic, username: a:b}}\n": "http|git.inject.username",
		"    git: {url: \"https://git.example.com\", inject: {scheme: bearer, username: a}}\n":  "http|git.inject.username",
		"    git: {url: \"https://git.example.com\", other: 1}\n":                               "http|git.other",
		"    git: {url: \"https://git.example.com\", inject: {scheme: bearer, port: 1}}\n":      "http|git.inject.port",
		"    http: {read_only: [\"post /x\"]}\n":                                                "http|http.read_only[0]",
		"    http: {read_only: [\"POST x\"]}\n":                                                 "http|http.read_only[0]",
		"    http: {read_only: [\"POST\"]}\n":                                                   "http|http.read_only[0]",
		"    http: {pass: [Authorization]}\n":                                                   "http|http.pass[0]",
		"    http: {pass: [Cookie]}\n":                                                          "http|http.pass[0]",
		"    http: {pass: [\"X A\"]}\n":                                                         "http|http.pass[0]",
		"    http: {pass_back: [\"\"]}\n":                                                       "http|http.pass_back[0]",
		"    http: {other: [x]}\n":                                                              "http|http.other",
	}
	for extra, want := range bad {
		kind, member, _ := strings.Cut(want, "|")
		if kind == "kind mcp" {
			kind = "mcp"
		}
		_, err := load(t, entry(kind, extra))
		if err == nil || !strings.Contains(err.Error(), `connectors[0] "api": `+member) {
			t.Errorf("%s: want a problem with %s, got %v", extra, member, err)
		}
	}
	// A token connector's own header is the credential's.
	own := "connectors:\n  - name: api\n    title: API\n    kind: http\n    url: https://api.example.com\n" +
		"    auth: {type: token, inject: {header: X-Key}}\n    http: {pass: [x-key]}\n"
	if _, err := load(t, own); err == nil || !strings.Contains(err.Error(), "http.pass[0]") {
		t.Errorf("the credential's header passes: %v", err)
	}
}
