// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"latere.ai/x/pons/catalog"
)

// An IP literal in each notation, a single label, localhost and a name under
// local, internal or home.arpa are refused; names are compared normalized.
func TestHostRule(t *testing.T) {
	refused := []string{
		"", "localhost", "LOCALHOST.", "api.localhost", "printer.local", "db.internal", "nas.home.arpa", "home.arpa",
		"10.0.0.1", "127.0.0.1", "169.254.169.254", "10.1", "0x7f.1", "0x7f000001", "2130706433", "017700000001",
		"a.0x10", "::1", "[::1]", "fe80::1", "metadata", "example", "*.example.com", "a.*.example.com",
		"exa mple.com", "bücher.example", "-a.example.com", "a..example.com", "example.com:443",
	}
	for _, h := range refused {
		if err := catalog.CheckHost(h); !errors.Is(err, catalog.ErrHostNotAName) {
			t.Errorf("CheckHost(%q) = %v", h, err)
		}
	}
	admitted := []string{"example.com", "API.Example.COM.", "mcp.tracker.example.com", "xn--bcher-kva.example", "a1.example.net", "internal.example.com", "local.example.com"}
	for _, h := range admitted {
		if err := catalog.CheckHost(h); err != nil {
			t.Errorf("CheckHost(%q) = %v", h, err)
		}
	}
	if err := catalog.CheckPattern("*.example.com"); err != nil {
		t.Errorf("a leading wildcard pattern: %v", err)
	}
	for _, p := range []string{"*.*.example.com", "*.com.", "*.localhost", "*.10.0.0.1", "*"} {
		if catalog.CheckPattern(p) == nil {
			t.Errorf("CheckPattern(%q) admitted", p)
		}
	}
	if catalog.ErrHostNotAName.Error() != "host_not_a_name" {
		t.Error("the refusal's text is its name")
	}
	if catalog.Normalize(" Api.Example.COM. ") != "api.example.com" {
		t.Error("Normalize")
	}
}

// *.example.com does not cover example.com, and absent hosts are the host
// of url.
func TestHostsCoverTheURL(t *testing.T) {
	m := catalog.Matcher([]string{"*.Example.com", "api.other.example.org."})
	for host, want := range map[string]bool{
		"mcp.example.com": true, "a.b.example.com": true, "example.com": false, "api.other.example.org": true,
		"other.example.org": false, "": false,
	} {
		if m.Matches(catalog.Normalize(host)) != want {
			t.Errorf("Matches(%q) != %v", host, want)
		}
	}
	entry := catalog.Connector{Name: "x", Title: "X", Kind: "mcp", URL: "https://example.com/mcp", Hosts: []string{"*.example.com"}, Auth: catalog.Auth{Type: "none"}}
	if ps := catalog.Validate(entry, false); len(ps) != 1 || ps[0].Field != "hosts" {
		t.Fatalf("a wildcard that misses the bare name: %v", ps)
	}
	entry.Hosts = nil
	if ps := catalog.Validate(entry, false); len(ps) != 0 {
		t.Fatalf("absent hosts: %v", ps)
	}
}

// The effect is read only for a tool a read_only glob matches, and a glob
// matches a whole name by case.
func TestEffect(t *testing.T) {
	m := catalog.Marks{ReadOnly: []string{"get_*", "list_*", "*_status", "exact"}, Hidden: []string{"delete_*"}}
	for tool, want := range map[string]string{
		"get_issue": "read", "list_": "read", "job_status": "read", "exact": "read",
		"Get_issue": "write", "create_issue": "write", "exactly": "write", "delete_project": "write", "": "write",
	} {
		if got := m.Effect(tool); got != want {
			t.Errorf("Effect(%q) = %s, want %s", tool, got, want)
		}
	}
	if (catalog.Marks{}).Effect("get_issue") != catalog.EffectWrite {
		t.Error("an entry with no marks makes every tool write")
	}
	if !m.IsHidden("delete_project") || m.IsHidden("get_issue") {
		t.Error("IsHidden")
	}
	for _, tc := range []struct {
		glob, name string
		want       bool
	}{
		{"*", "", true}, {"*", "anything", true}, {"", "", false}, {"a*b*c", "abc", true}, {"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false}, {"**", "x", true}, {"a*", "b", false}, {"*a", "ba", true}, {"*a", "ab", false},
		{"a.b", "a.b", true}, {"a?b", "axb", false},
	} {
		if catalog.Glob(tc.glob, tc.name) != tc.want {
			t.Errorf("Glob(%q, %q) != %v", tc.glob, tc.name, tc.want)
		}
	}
}

// FuzzGlob holds Glob to a regular expression built from the same glob.
func FuzzGlob(f *testing.F) {
	for _, seed := range [][2]string{{"get_*", "get_issue"}, {"*a*", "banana"}, {"a*b", "ab"}, {"*", ""}, {"x", "y"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, glob, name string) {
		if glob == "" {
			if catalog.Glob(glob, name) {
				t.Fatal("an empty glob matched")
			}
			return
		}
		if !utf8.ValidString(glob) || !utf8.ValidString(name) {
			// The expression reads runes and the glob bytes; on valid
			// text the two agree, and that is what is compared.
			return
		}
		parts := strings.Split(glob, "*")
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		re := regexp.MustCompile(`(?s)^` + strings.Join(parts, ".*") + `$`)
		if got, want := catalog.Glob(glob, name), re.MatchString(name); got != want {
			t.Fatalf("Glob(%q, %q) = %v, the expression says %v", glob, name, got, want)
		}
	})
}
