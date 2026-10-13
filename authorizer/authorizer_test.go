// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
)

// specRow is one row of the vocabulary table of spec 004: the fields it
// names, and whether it names the envelope's id.
type specRow struct {
	kind, action string
	fields       []string
	id           bool
}

// specTable reads the vocabulary table of spec 004.
func specTable(t *testing.T) []specRow {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "specs", "004-identity-and-authorization.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	row := regexp.MustCompile("^\\| `(Connector|Connection)` \\| `([a-z]+\\.[a-z]+)` \\| (.*) \\|$")
	word := regexp.MustCompile("`([a-z_]+)`")
	var rows []specRow
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		m := row.FindStringSubmatch(scan.Text())
		if m == nil {
			continue
		}
		r := specRow{kind: m[1], action: m[2]}
		for _, w := range word.FindAllStringSubmatch(m[3], -1) {
			switch {
			case w[1] == "id":
				r.id = true
			case !slices.Contains(r.fields, w[1]):
				r.fields = append(r.fields, w[1])
			}
		}
		rows = append(rows, r)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

// The constants of the package are the vocabulary table of spec 004, in its
// order, with its fields.
func TestTheVocabularyIsTheSpecs(t *testing.T) {
	rows := specTable(t)
	if len(rows) == 0 {
		t.Fatal("no row of the vocabulary table was read")
	}
	actions := authorizer.Actions()
	if len(actions) != len(rows) {
		t.Fatalf("the package has %d actions and the spec %d", len(actions), len(rows))
	}
	v := authorizer.Vocabulary()
	if v.Core != authorizer.Core || len(v.Actions) != len(rows) {
		t.Fatalf("the vocabulary is %+v", v)
	}
	for i, r := range rows {
		if actions[i] != r.action {
			t.Errorf("row %d: the package has %q and the spec %q", i, actions[i], r.action)
		}
		if got := authorizer.Kind(r.action); got != r.kind {
			t.Errorf("%s acts on %q, the spec says %q", r.action, got, r.kind)
		}
		if !authorizer.Known(r.action) {
			t.Errorf("%s is not known", r.action)
		}
		if got := authorizer.Fields(r.action); !slices.Equal(got, r.fields) {
			t.Errorf("%s sends %v, the spec says %v", r.action, got, r.fields)
		}
		if got := authorizer.SendsID(r.action); got != r.id {
			t.Errorf("%s sends an id: %v, the spec says %v", r.action, got, r.id)
		}
	}
	if authorizer.Known("connection.steal") || authorizer.Kind("connection.steal") != "" || authorizer.Fields("x") != nil || authorizer.SendsID("x") {
		t.Error("a string outside the table is an action")
	}
	if v.Label(authorizer.KindConnection) != "Connections" {
		t.Error("the kinds carry no label")
	}
}

// The envelope keeps kind and id for the resource itself and drops a field
// of either name, so no action's fields take one: a connection's kind named
// kind never reached an authorizer.
func TestNoFieldTakesANameTheEnvelopeKeeps(t *testing.T) {
	for _, action := range authorizer.Actions() {
		for _, f := range authorizer.Fields(action) {
			if f == "kind" || f == "id" {
				t.Errorf("%s sends a field named %q, which the envelope keeps for the resource", action, f)
			}
		}
	}
}

// A question with every field of its action set, its kind and its id,
// encoded as Pons posts it and decoded as an authorizer reads it, carries
// each of them as it was sent.
func TestEveryFieldSurvivesTheWire(t *testing.T) {
	for _, action := range authorizer.Actions() {
		fields := map[string]any{}
		for _, f := range authorizer.Fields(action) {
			fields[f] = "the " + f
		}
		if slices.Contains(authorizer.Fields(action), authorizer.FieldRefs) {
			fields[authorizer.FieldRefs] = []any{"refs/heads/agents/a", "refs/heads/agents/b"}
		}
		id := ""
		if authorizer.SendsID(action) {
			id = "con_01"
		}
		sent := authz.Request{
			Subject: "https://issuer.example.com|alice", Issuer: "https://issuer.example.com", Sub: "alice",
			Action: action, Resource: authz.NewResource(authorizer.Kind(action), id, fields),
		}
		raw, err := json.Marshal(sent)
		if err != nil {
			t.Fatal(err)
		}
		var got authz.Request
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.Action != action || got.Resource.Kind != authorizer.Kind(action) || got.Resource.ID != id {
			t.Errorf("%s arrived as %s on %q %q", action, got.Action, got.Resource.Kind, got.Resource.ID)
		}
		if len(got.Resource.Fields) != len(fields) {
			t.Errorf("%s sent %d fields and %d arrived: %v", action, len(fields), len(got.Resource.Fields), got.Resource.Fields)
		}
		for name, want := range fields {
			if v, ok := got.Resource.Fields[name]; !ok || !reflect.DeepEqual(v, want) {
				t.Errorf("%s: %s arrived as %v, %v", action, name, v, ok)
			}
		}
	}
}

// What the table holds is spelled once: the connector's kind on the
// actions about a connector, the connection's on those about a connection.
func TestEachKindIsNamedForItsResource(t *testing.T) {
	for _, action := range authorizer.Actions() {
		fields := authorizer.Fields(action)
		switch authorizer.Kind(action) {
		case authorizer.KindConnector:
			if slices.Contains(fields, authorizer.FieldConnectionKind) {
				t.Errorf("%s sends a connection's kind", action)
			}
		case authorizer.KindConnection:
			if slices.Contains(fields, authorizer.FieldConnectorKind) {
				t.Errorf("%s sends a connector's kind", action)
			}
		}
	}
}

// DecodeLimits refuses what Pons cannot hold: an object that does not parse,
// an unknown key, a negative figure and an empty glob.
func TestDecodeRefusesWhatItCannotHold(t *testing.T) {
	for _, raw := range []string{
		`[]`, `{"owner": 1}`, `{"max_connections": "5"}`, `{"plan": "pro"}`, `{"owner": "x", "Owner": "y"}`,
		`{"max_connections": -1}`, `{"calls_per_minute": -5}`,
		`{"connectors": [""]}`, `{"tools": ["get_*", ""]}`, `{"refs": [""]}`, `{} {}`, `{`,
		`{"requests": [""]}`, `{"requests": ["GET"]}`, `{"requests": ["get /x"]}`, `{"requests": ["GET x"]}`,
		`{"requests": ["GET  /x"]}`, `{"requests": ["GET /a/**/b"]}`, `{"requests": ["GET /a*"]}`, `{"requests": ["GET /a//b"]}`,
		`{"requests": ["GET /a/"]}`, `{"requests": ["POST/x"]}`,
	} {
		_, err := authorizer.DecodeLimits(authz.Decision{Allow: true, Limits: json.RawMessage(raw)})
		if !errors.Is(err, authorizer.ErrUnreadableLimits) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{``, `null`, ` {} `} {
		l, err := authorizer.DecodeLimits(authz.Decision{Allow: true, Limits: json.RawMessage(raw)})
		if err != nil || !isZero(l) {
			t.Errorf("%q: %+v, %v", raw, l, err)
		}
	}
}

func isZero(l authorizer.Limits) bool {
	return l.Owner == "" && l.MaxConnections == 0 && l.Connectors == nil && !l.ReadOnly && l.Tools == nil && l.Refs == nil && l.Requests == nil && l.CallsPerMinute == 0
}

// The limits object carries exactly the eight keys, and DecodeLimits reads
// back what an authorizer renders.
func TestTheWireNamesEveryMemberAndNoOther(t *testing.T) {
	full := authorizer.Limits{
		Owner: "https://issuer.example.com|team", MaxConnections: 3, Connectors: []string{"notion", "ctr_*"},
		ReadOnly: true, Tools: []string{"get_*"}, Refs: []string{"refs/heads/agent/*"}, CallsPerMinute: 60,
		Requests: []string{"GET /**", "POST /repos/*/*/issues", "GET /"},
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	want := []string{"calls_per_minute", "connectors", "max_connections", "owner", "read_only", "refs", "requests", "tools"}
	if !slices.Equal(names, want) {
		t.Fatalf("the wire names %v, want %v", names, want)
	}
	back, err := authorizer.DecodeLimits(authz.Decision{Allow: true, Limits: raw})
	if err != nil {
		t.Fatal(err)
	}
	if back.Owner != full.Owner || back.MaxConnections != 3 || !slices.Equal(back.Connectors, full.Connectors) ||
		!back.ReadOnly || !slices.Equal(back.Tools, full.Tools) || !slices.Equal(back.Refs, full.Refs) || back.CallsPerMinute != 60 ||
		!slices.Equal(back.Requests, full.Requests) {
		t.Fatalf("read back %+v", back)
	}
	if empty, _ := json.Marshal(authorizer.Limits{}); string(empty) != "{}" {
		t.Fatalf("an empty limits object renders %s", empty)
	}
}

func TestWhatALimitAdmits(t *testing.T) {
	var none authorizer.Limits
	if !none.AdmitsConnector("ctr_1") || !none.AdmitsTool("delete_everything") {
		t.Error("empty globs admit nothing")
	}
	l := authorizer.Limits{Connectors: []string{"notion", "git*"}, Tools: []string{"get_*"}}
	for ref, want := range map[string]bool{"notion": true, "github": true, "ctr_01": false, "Notion": false} {
		if l.AdmitsConnector(ref) != want {
			t.Errorf("AdmitsConnector(%q) != %v", ref, want)
		}
	}
	if !(authorizer.Limits{Connectors: []string{"ctr_*"}}).AdmitsConnector("ctr_01jb") {
		t.Error("ctr_* does not admit an added connector")
	}
	if !l.AdmitsTool("get_issue") || l.AdmitsTool("create_issue") {
		t.Error("tools")
	}
	refs := authorizer.Limits{Refs: []string{"refs/heads/agent/*"}}
	if !none.AdmitsRef("refs/heads/main") || !refs.AdmitsRef("refs/heads/agent/fix") || refs.AdmitsRef("refs/heads/main") {
		t.Error("refs")
	}
	cases := []struct{ named, installation, want int }{
		{0, 100, 100}, {5, 100, 5}, {500, 100, 100}, {5, 0, 5}, {0, 0, 0},
	}
	for _, c := range cases {
		if got := (authorizer.Limits{MaxConnections: c.named}).Cap(c.installation); got != c.want {
			t.Errorf("Cap(%d) under %d = %d, want %d", c.installation, c.named, got, c.want)
		}
	}
}

// The doc's example subject renders as authz renders one.
func TestTheSubjectShape(t *testing.T) {
	if got := authz.Subject("https://issuer.example.com/", "alice"); !strings.HasSuffix(got, "|alice") {
		t.Fatalf("subject %q", got)
	}
}

// Requests admits a request by its method and its path's segments: `*` is
// one non-empty segment and never spans a `/`, a last `**` is the rest of
// the path, the pattern `/` is the address itself, and an empty list admits
// every request.
func TestWhatRequestsAdmit(t *testing.T) {
	if !(authorizer.Limits{}).AdmitsRequest("DELETE", "/repos/acme/app") {
		t.Error("no requests admits nothing")
	}
	l := authorizer.Limits{Requests: []string{
		"GET /**", "PATCH /repos/*/*/pulls/*", "PUT /repos/*/*/pulls/*/reviews/*", "POST /gmail/v1/users/*/drafts", "POST /",
	}}
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/", true},
		{"GET", "/repos/acme/app/pulls/7/merge", true},
		{"PATCH", "/repos/acme/app/pulls/7", true},
		{"PATCH", "/repos/acme/app/pulls/7/merge", false},
		{"PUT", "/repos/acme/app/pulls/7/reviews/3", true},
		{"PUT", "/repos/acme/app/pulls/7/reviews/3/dismissals", false},
		{"PUT", "/repos/acme/app/pulls/7/merge", false},
		{"POST", "/gmail/v1/users/me/drafts", true},
		{"POST", "/gmail/v1/users/me/drafts/send", false},
		{"POST", "/gmail/v1/users/me/messages/send", false},
		{"POST", "/", true},
		{"POST", "/x", false},
		{"get", "/repos", false},
		{"HEAD", "/repos", false},
	} {
		if got := l.AdmitsRequest(c.method, c.path); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.path, got, c.want)
		}
	}
	under := authorizer.Limits{Requests: []string{"GET /calendar/v3/**"}}
	for path, want := range map[string]bool{
		"/calendar/v3/calendars/primary/events": true, "/calendar/v3": true, "/calendar/v3x/y": false, "/drive/v3/files": false, "/calendar": false,
	} {
		if got := under.AdmitsRequest("GET", path); got != want {
			t.Errorf("GET %s under /calendar/v3/**: %v, want %v", path, got, want)
		}
	}
}
