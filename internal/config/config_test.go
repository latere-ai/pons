// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// env is a test's environment.
type env map[string]string

func (e env) get(name string) string { return e[name] }

// minimal is the smallest environment a server starts with.
func minimal() env {
	return env{
		"PONS_PUBLIC_URL":   "http://localhost:8080",
		"PONS_OIDC_ISSUERS": "https://issuer.example.com",
	}
}

func key(b byte) string {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

// The table of specs/011-distribution.md lists every variable the binary
// reads and none it does not.
func TestTableMatchesWhatIsRead(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "specs", "011-distribution.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	row := regexp.MustCompile("^\\| `(PONS_[A-Z_]+)` \\|")
	var table []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if m := row.FindStringSubmatch(scan.Text()); m != nil {
			table = append(table, m[1])
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	read := Variables()
	slices.Sort(table)
	slices.Sort(read)
	if !slices.Equal(table, read) {
		t.Fatalf("the table of spec 011 lists\n  %v\nand the binary reads\n  %v", table, read)
	}
}

// A missing required variable and a value that does not parse each stop
// the start with the variable's name and never its value.
func TestErrorsNameTheVariableOnly(t *testing.T) {
	const marker = "canary-value-0042"
	cases := []struct {
		name, variable, value string
	}{
		{"public url not a url", "PONS_PUBLIC_URL", "ftp://" + marker},
		{"public url with a query", "PONS_PUBLIC_URL", "https://pons.example.com/?" + marker},
		{"base path", "PONS_BASE_PATH", marker},
		{"a key", "PONS_SEALING_KEYS", marker},
		{"a second key", "PONS_SEALING_KEYS", key(1) + "," + marker},
		{"a short key", "PONS_SEALING_KEYS", base64.StdEncoding.EncodeToString([]byte(marker))},
		{"an issuer", "PONS_OIDC_ISSUERS", marker},
		{"the authorizer", "PONS_AUTHORIZER_URL", "mailto:" + marker},
		{"a return url", "PONS_RETURN_URLS", "https://app.example.com/#" + marker},
		{"a return url that is not one", "PONS_RETURN_URLS", marker},
		{"the client uri", "PONS_CLIENT_URI", marker},
		{"retention", "PONS_RECORDS_RETENTION", marker},
		{"a negative retention", "PONS_RECORDS_RETENTION", "-1h"},
		{"a count", "PONS_MAX_CONNECTIONS_PER_OWNER", marker},
		{"a zero count", "PONS_MAX_INFLIGHT", "0"},
		{"a size", "PONS_MAX_REQUEST_BYTES", marker},
		{"a timeout", "PONS_CALL_HEADER_TIMEOUT", marker},
		{"the proxy", "PONS_OUTBOUND_PROXY", "socks5://" + marker},
		{"the switch", "PONS_DIAL_ALLOW_PRIVATE", marker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := minimal()
			e[tc.variable] = tc.value
			_, err := FromEnv(e.get)
			if err == nil {
				t.Fatalf("%s=%q was accepted", tc.variable, tc.value)
			}
			if !strings.Contains(err.Error(), tc.variable) {
				t.Errorf("the error does not name %s: %v", tc.variable, err)
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), tc.value) {
				t.Errorf("the error repeats the value: %v", err)
			}
		})
	}
	for _, required := range []string{"PONS_PUBLIC_URL", "PONS_OIDC_ISSUERS"} {
		e := minimal()
		delete(e, required)
		if _, err := FromEnv(e.get); err == nil || !strings.Contains(err.Error(), required) {
			t.Errorf("without %s: %v", required, err)
		}
	}
}

// The defaults are the table's.
func TestDefaults(t *testing.T) {
	s, err := FromEnv(minimal().get)
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{
		Addr: ":8080", PublicURL: "http://localhost:8080", BasePath: "/v1",
		OIDCIssuers: []string{"https://issuer.example.com"}, OIDCAudiences: []string{"pons"},
		ClientName: "Pons", RecordsRetention: 720 * time.Hour,
		MaxConnectionsPerOwner: 100, CreatesPerMinute: 10, MaxInflightPerSubject: 32, MaxInflight: 1024,
		MaxRequestBytes: 4 << 20, CallHeaderTimeout: 30 * time.Second, StreamIdleTimeout: 5 * time.Minute,
	}
	if fmt.Sprint(s) != fmt.Sprint(want) {
		t.Fatalf("defaults\n got %+v\nwant %+v", s, want)
	}
	if s.Durable() {
		t.Error("a server with no database is durable")
	}
}

// Every variable set, read into its field.
func TestEveryVariableIsRead(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("authorizer-bearer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := env{
		"PONS_ADDR":                      "127.0.0.1:9000",
		"PONS_PUBLIC_URL":                "https://pons.example.com/prefix/",
		"PONS_BASE_PATH":                 "/api/",
		"PONS_DATABASE_URL":              "postgres://pons@db.example.com/pons",
		"PONS_DATABASE_POOL_URL":         "postgres://pons@pool.example.com/pons",
		"PONS_SEALING_KEYS":              key(1) + ", " + strings.TrimRight(base64.URLEncoding.EncodeToString(make([]byte, 32)), "="),
		"PONS_OIDC_ISSUERS":              "https://a.example.com/, https://b.example.com",
		"PONS_OIDC_AUDIENCE":             "pons, other",
		"PONS_AUTHORIZER_URL":            "http://authorizer.example.com/decide",
		"PONS_AUTHORIZER_TOKEN_FILE":     tokenFile,
		"PONS_CATALOG_FILE":              "/etc/pons/catalog.yaml",
		"PONS_RETURN_URLS":               "https://app.example.com/done, https://app.example.com/settings/",
		"PONS_CLIENT_NAME":               "Example",
		"PONS_CLIENT_URI":                "https://www.example.com",
		"PONS_RECORDS_RETENTION":         "24h",
		"PONS_MAX_CONNECTIONS_PER_OWNER": "5",
		"PONS_CREATES_PER_MINUTE":        "2",
		"PONS_MAX_INFLIGHT_PER_SUBJECT":  "3",
		"PONS_MAX_INFLIGHT":              "4",
		"PONS_MAX_REQUEST_BYTES":         "1024",
		"PONS_CALL_HEADER_TIMEOUT":       "5s",
		"PONS_STREAM_IDLE_TIMEOUT":       "1m",
		"PONS_OUTBOUND_PROXY":            "http://user:pass@proxy.example.com:3128",
		"PONS_DIAL_ALLOW_PRIVATE":        "1",
	}
	s, err := FromEnv(e.get)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case s.Addr != "127.0.0.1:9000", s.PublicURL != "https://pons.example.com/prefix", s.BasePath != "/api":
		t.Errorf("addresses: %q %q %q", s.Addr, s.PublicURL, s.BasePath)
	case !s.Durable() || s.ServingURL() != e["PONS_DATABASE_POOL_URL"]:
		t.Errorf("the serving URL is not the pooled one")
	case len(s.SealingKeys) != 2 || s.SealingKeys[0][0] != 1 || s.SealingKeys[1][0] != 0:
		t.Errorf("the keys were not read in order")
	case !slices.Equal(s.OIDCIssuers, []string{"https://a.example.com", "https://b.example.com"}):
		t.Errorf("issuers %v", s.OIDCIssuers)
	case !slices.Equal(s.OIDCAudiences, []string{"pons", "other"}):
		t.Errorf("audiences %v", s.OIDCAudiences)
	case s.AuthorizerToken.Reveal() != "authorizer-bearer":
		t.Errorf("the token file was not read")
	case len(s.ReturnURLs) != 2 || s.ClientName != "Example" || s.ClientURI == "" || s.CatalogFile == "":
		t.Errorf("sign-in settings %+v", s)
	case s.RecordsRetention != 24*time.Hour || s.MaxConnectionsPerOwner != 5 || s.CreatesPerMinute != 2 ||
		s.MaxInflightPerSubject != 3 || s.MaxInflight != 4 || s.MaxRequestBytes != 1024 ||
		s.CallHeaderTimeout != 5*time.Second || s.StreamIdleTimeout != time.Minute:
		t.Errorf("limits %+v", s)
	case s.OutboundProxy == nil || s.OutboundProxy.Host != "proxy.example.com:3128" || !s.DialAllowPrivate:
		t.Errorf("outbound %+v", s)
	}
	direct := Settings{DatabaseURL: "postgres://x"}
	if direct.ServingURL() != "postgres://x" {
		t.Error("with no pooled URL the serving URL is the direct one")
	}
	e["PONS_BASE_PATH"] = "/"
	if s, err = FromEnv(e.get); err != nil || s.BasePath != "" {
		t.Errorf("a base path of / is the root: %q, %v", s.BasePath, err)
	}
}

// The refusals that need the settings alone.
func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		set   env
		names string
	}{
		{"http with a database", env{"PONS_DATABASE_URL": "postgres://x", "PONS_SEALING_KEYS": key(1)}, "PONS_PUBLIC_URL"},
		{"no key with a database", env{"PONS_DATABASE_URL": "postgres://x", "PONS_PUBLIC_URL": "https://p.example.com"}, "PONS_SEALING_KEYS"},
		{"a pool and no database", env{"PONS_DATABASE_POOL_URL": "postgres://x"}, "PONS_DATABASE_URL"},
		{"a token file and no endpoint", env{"PONS_AUTHORIZER_TOKEN_FILE": empty}, "PONS_AUTHORIZER_URL"},
		{"an endpoint and no token file", env{"PONS_AUTHORIZER_URL": "https://a.example.com"}, "PONS_AUTHORIZER_TOKEN_FILE"},
		{"an endpoint and a missing file", env{"PONS_AUTHORIZER_URL": "https://a.example.com", "PONS_AUTHORIZER_TOKEN_FILE": filepath.Join(dir, "none")}, "PONS_AUTHORIZER_TOKEN_FILE"},
		{"an endpoint and an empty file", env{"PONS_AUTHORIZER_URL": "https://a.example.com", "PONS_AUTHORIZER_TOKEN_FILE": empty}, "PONS_AUTHORIZER_TOKEN_FILE"},
		{"an issuer twice", env{"PONS_OIDC_ISSUERS": "https://a.example.com, https://a.example.com/"}, "PONS_OIDC_ISSUERS"},
		{"a key twice", env{"PONS_SEALING_KEYS": key(1) + "," + key(1)}, "position 2"},
		{"an empty key entry", env{"PONS_SEALING_KEYS": key(1) + ","}, "position 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := minimal()
			for k, v := range tc.set {
				e[k] = v
			}
			_, err := FromEnv(e.get)
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("want a refusal naming %s, got %v", tc.names, err)
			}
		})
	}
	// http is accepted on the memory store.
	if _, err := FromEnv(minimal().get); err != nil {
		t.Fatalf("http on the memory store: %v", err)
	}
}

// A secret and a key never print.
func TestSecretsDoNotPrint(t *testing.T) {
	s := NewSecret("the-bearer-value")
	k := SealingKey{1, 2, 3}
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %x", s, s, s, s, s),
		fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, k),
		s.LogValue().String(), k.LogValue().String(),
	} {
		if strings.Contains(out, "the-bearer-value") || strings.Contains(out, "1 2 3") {
			t.Fatalf("a secret printed: %s", out)
		}
	}
	var b strings.Builder
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "token", s, "key", k)
	if strings.Contains(b.String(), "the-bearer-value") {
		t.Fatalf("a secret was logged: %s", b.String())
	}
	if s.Empty() || !NewSecret("").Empty() {
		t.Error("Empty")
	}
}
