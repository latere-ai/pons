// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

func client(t *testing.T) *http.Client {
	t.Helper()
	roots, err := stubs.Roots()
	if err != nil {
		t.Fatal(err)
	}
	return dial.Operator(dial.OperatorOptions{Roots: roots})
}

// The stub authorizer answers over TLS from its table and records every
// question it was asked.
func TestAuthorizerRecordsEveryQuestion(t *testing.T) {
	a := stubs.NewAuthorizer(t, stub.WithAllow())
	if !strings.HasPrefix(a.URL(), "https://127.0.0.1:") {
		t.Fatalf("the stub is not on loopback over TLS: %s", a.URL())
	}
	a.Allow(stub.Rule{Subject: "https://issuer.example.com|alice", Action: authorizer.ActionConnectionRead})
	c, err := authz.NewClient(authz.Options{URL: a.URL(), Token: a.Token(), HTTP: client(t), Vocabulary: authorizer.Vocabulary()})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(subject, action, id string) bool {
		d, err := c.Authorize(context.Background(), authz.Request{
			Subject: subject, Claims: map[string]any{}, Action: action,
			Resource: authz.NewResource(authorizer.Kind(action), id, nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		return d.Allow
	}
	if !ask("https://issuer.example.com|alice", authorizer.ActionConnectionRead, "con_1") {
		t.Error("the rule's question is denied")
	}
	if ask("https://issuer.example.com|bob", authorizer.ActionConnectionRead, "con_2") {
		t.Error("a question no rule allows is allowed")
	}
	got := a.Requests()
	if len(got) != 2 || got[0].Resource.ID != "con_1" || got[1].Subject != "https://issuer.example.com|bob" {
		t.Fatalf("the stub recorded %+v", got)
	}
	if err := authz.Check(context.Background(), c, authorizer.ActionConnectionRead, authorizer.KindConnection); err != nil {
		t.Fatalf("the stub does not deny the probe: %v", err)
	}
}

// The stub issuer serves its discovery document and key set over TLS and
// mints tokens with a session claim.
func TestIssuerMintsForTheServer(t *testing.T) {
	iss := stubs.NewIssuer(t)
	resp, err := client(t).Get(iss.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Issuer != iss.URL() || doc.JWKSURI != iss.JWKSURL() {
		t.Fatalf("discovery %s: %v", body, err)
	}
	tok := iss.Token("alice", map[string]any{"session": "ses_1"})
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not a token: %q", tok)
	}
	if got := iss.Subject("alice"); got != iss.URL()+"|alice" {
		t.Fatalf("subject %q", got)
	}
	if _, err := stubs.Certificate("api.example.com", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
