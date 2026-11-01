// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// The variables that carry what this check needs from the operator: a
// real Google OAuth client of specs/015-google-connectors.md's shape, and
// a refresh token already granted the union of the three entries' scopes
// by a real Google account. CONTRIBUTING.md's "A further check against
// the real Google" and the spec name where each comes from.
const (
	envGoogleLiveClientID     = "GOOGLE_LIVE_CLIENT_ID"
	envGoogleLiveClientSecret = "GOOGLE_LIVE_CLIENT_SECRET"
	envGoogleLiveRefreshToken = "GOOGLE_LIVE_REFRESH_TOKEN"
)

// googleLiveEntries is the YAML block under "### The entries" of spec
// 015, unread and unchanged but for the example client id: the entry the
// spec shows is the entry this check loads, so the two cannot drift apart
// silently.
func googleLiveEntries(t testing.TB, clientID string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "015-google-connectors.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "### The entries\n")
	if !ok {
		t.Fatal(`specs/015-google-connectors.md has no section "### The entries"`)
	}
	_, block, ok := strings.Cut(after, "```yaml\n")
	if !ok {
		t.Fatal(`the section "### The entries" has no yaml block`)
	}
	block, _, _ = strings.Cut(block, "```")
	const example = "123456789012-example.apps.googleusercontent.com"
	if !strings.Contains(block, example) {
		t.Fatalf("the entries no longer name the example client id %q; update this check", example)
	}
	return strings.ReplaceAll(block, example, clientID)
}

// startGoogleLiveStack starts ponsd with the Google entries and the real
// outside world reachable: unlike startStack, no Permit narrows the
// outside client to a stub's listeners and no resolver or roots replace
// the process's, so a request to Google's own hosts leaves for the real
// internet (specs/009-outbound-requests.md's default: a public address on
// its catalog port). The issuer and the authorizer stay the stubs', which
// the access package reaches over its own client, not the outside one.
func startGoogleLiveStack(t testing.TB, iss *stubs.Issuer, env map[string]string) *stack {
	t.Helper()
	s := &stack{t: t, iss: iss, logs: &syncBuffer{}, env: env}
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, func(k string) string { return s.env[k] }, s.logs, Hooks{
			Ready: ready, Roots: stubs.Roots(), Store: func(st store.Store) { s.store = st },
		})
	}()
	select {
	case addr := <-ready:
		s.base = "http://" + addr
	case err := <-done:
		cancel()
		t.Fatalf("the server did not start: %v\n%s", err, s.logs)
	case <-time.After(60 * time.Second):
		cancel()
		t.Fatalf("the server did not start in time\n%s", s.logs)
	}
	var once sync.Once
	s.stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("the server stopped with %v", err)
			}
		})
	}
	t.Cleanup(s.stop)
	return s
}

// seedGoogleConnection writes a connection already connected with the
// refresh token, bound exactly as a confirmed sign-in would bind it
// (specs/007-sign-in.md): the next call's credential is open for one
// minute's grace, so Signin.Due answers true and the first call refreshes
// it at Google's token endpoint before forwarding.
func seedGoogleConnection(t testing.TB, s *stack, sealer *store.KeySealer, owner, connector, clientID, refreshToken string, scopes []string) string {
	t.Helper()
	connID := id.New(id.Connection)
	row := store.Connection{
		ID: connID, Owner: owner, Name: connector, Connector: connector,
		Kind: catalog.KindHTTP, Auth: catalog.AuthOAuth, State: store.StateConnected, CreatedBy: owner,
	}
	if err := s.store.Connections().Create(t.Context(), row, 0); err != nil {
		t.Fatal(err)
	}
	meta := store.Meta{
		TokenType: "Bearer",
		// In the past, so Due answers true on the very first call.
		AccessExpiresAt:    time.Now().Add(-time.Hour).UTC(),
		Issuer:             "https://accounts.google.com",
		TokenEndpoint:      "https://oauth2.googleapis.com/token",
		RevocationEndpoint: "https://oauth2.googleapis.com/revoke",
		ClientID:           clientID,
		Scopes:             scopes,
	}
	secrets := store.Secrets{RefreshToken: refreshToken}
	plain, err := secrets.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(plain, store.CredentialBinding(connID, owner, catalog.AuthOAuth, meta, ""))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.Credentials().Put(t.Context(), connID, store.SealedCredential{Kind: catalog.AuthOAuth, Meta: doc, Sealed: sealed}); err != nil {
		t.Fatal(err)
	}
	return connID
}

// TestGoogleRealForwarding is specs/015-google-connectors.md's check
// against the real Google. It is skipped unless GOOGLE_LIVE_CLIENT_ID,
// GOOGLE_LIVE_CLIENT_SECRET and GOOGLE_LIVE_REFRESH_TOKEN name a real
// Google OAuth client of the spec's shape and a refresh token a real
// Google account already granted the union of the three entries' scopes.
//
// It seeds each of the three connections with that refresh token, as a
// confirmed sign-in would leave them, then calls each one's forwarding
// address for real: the credential is due for a refresh on the first
// call, which asks Google's real token endpoint, and the forwarded call
// reaches Gmail, Calendar or Drive for real. Every call is read-only: it
// lists a few messages, events or files and changes nothing. It then
// asks each connector a write the installation's allow does not admit,
// gmail.compose's own send included, and checks the authorizer's
// "requests" limit refuses it before the request ever reaches Google.
//
// It proves the forwarding path and the authorizer's refusal; it does not
// run the sign-in itself (so it reads no account email), and it does not
// disconnect a connection or revoke at Google, which still need a person
// at a browser (this spec's Outcome records that run).
func TestGoogleRealForwarding(t *testing.T) {
	clientID := os.Getenv(envGoogleLiveClientID)
	secret := os.Getenv(envGoogleLiveClientSecret)
	refreshToken := os.Getenv(envGoogleLiveRefreshToken)
	if clientID == "" || secret == "" || refreshToken == "" {
		t.Skipf("set %s, %s and %s to a real Google OAuth client and a refresh token to run this check against the real Google; see specs/015-google-connectors.md", envGoogleLiveClientID, envGoogleLiveClientSecret, envGoogleLiveRefreshToken)
	}
	// The catalog's client secret resolves by the literal reference the
	// spec's entries carry, read from the real process environment
	// (internal/config.LookupEnv), not from this stack's own variables.
	t.Setenv("GOOGLE_CLIENT_SECRET", secret)

	block := googleLiveEntries(t, clientID)
	parsed, err := catalog.Parse([]byte(block), catalog.Options{LookupEnv: func(name string) (string, bool) {
		return secret, name == "GOOGLE_CLIENT_SECRET"
	}})
	if err != nil {
		t.Fatalf("the entries of spec 015 do not load: %v", err)
	}
	path := filepath.Join(t.TempDir(), "google.yaml")
	if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}

	iss := stubs.NewIssuer(t)
	az, authEnv := withAuthorizer(t, nil, stub.WithAllow("*"))
	// The installation reads; it writes nothing in this check, so every
	// write, the admitted drafts, events and files of the spec's table
	// included, is outside the allow and refused the same way.
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionUse, Limits: map[string]any{"requests": []string{"GET /**"}}})
	env := map[string]string{
		"PONS_ADDR": "127.0.0.1:0", "PONS_PUBLIC_URL": "http://127.0.0.1:8080",
		"PONS_OIDC_ISSUERS": iss.URL(), "PONS_SEALING_KEYS": key(9),
		"PONS_CATALOG_FILE": path,
	}
	maps.Copy(env, authEnv)
	s := startGoogleLiveStack(t, iss, env)

	var raw [32]byte
	for i := range raw {
		raw[i] = 9
	}
	sealer, err := store.NewSealer(raw)
	if err != nil {
		t.Fatal(err)
	}

	owner := iss.Subject("owner")
	scopesOf := func(name string) []string {
		c, ok := parsed.Get(name)
		if !ok {
			t.Fatalf("spec 015 no longer has the %s entry", name)
		}
		return c.Auth.Scopes
	}
	gmail := seedGoogleConnection(t, s, sealer, owner, "gmail", clientID, refreshToken, scopesOf("gmail"))
	calendar := seedGoogleConnection(t, s, sealer, owner, "google-calendar", clientID, refreshToken, scopesOf("google-calendar"))
	drive := seedGoogleConnection(t, s, sealer, owner, "google-drive", clientID, refreshToken, scopesOf("google-drive"))

	for _, tc := range []struct {
		name, read, write string
	}{
		{"gmail", "/users/me/messages?maxResults=3", "/users/me/drafts/send"},
		{"google-calendar", "/calendars/primary/events?maxResults=3", "/calendars/primary/acl"},
		{"google-drive", "/drive/v3/files?pageSize=3", "/drive/v3/files/a-file-id/permissions"},
	} {
		connID := map[string]string{"gmail": gmail, "google-calendar": calendar, "google-drive": drive}[tc.name]
		web := "/v1/connections/" + connID + "/http"
		if a := s.do(http.MethodGet, web+tc.read, "owner", nil); a.status != http.StatusOK {
			t.Fatalf("%s: a read: %d %s", tc.name, a.status, a.body)
		}
		if a := s.do(http.MethodPost, web+tc.write, "owner", map[string]any{}); a.status != http.StatusForbidden || a.detail("reason") != "requests" {
			t.Fatalf("%s: a write outside the allow: %d %s", tc.name, a.status, a.body)
		}
	}

	if strings.Contains(s.everything(), refreshToken) {
		t.Fatal("the refresh token reached a response or a log line")
	}
}
