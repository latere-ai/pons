// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// A connection's tools are its server's list through it, with the effect
// and the hidden mark its connector gives each; a server of an earlier
// revision is listed in a session it ends; a refused credential is
// refreshed once, or moves the connection; no call is recorded.
func TestToolsThroughAConnection(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, false)
	noted := r.noted()
	tools, err := r.c.Tools(ctx, noted)
	if err != nil || len(tools) != len(stubs.ConnectorTools) {
		t.Fatalf("%+v %v", tools, err)
	}
	for _, tool := range tools {
		want := catalog.EffectWrite
		if tool.Name == "search_notes" || tool.Name == "get_note" || tool.Name == "count" {
			want = catalog.EffectRead
		}
		if tool.Effect != want || tool.Hidden != (tool.Name == "delete_notebook") || tool.Description == "" {
			t.Errorf("%+v", tool)
		}
	}
	if len(r.calls(noted)) != 0 {
		t.Fatal("a list of tools recorded a call")
	}
	if creds := r.mcp.Credentials(); creds[len(creds)-1] != "Bearer the-notes-key-of-alice" {
		t.Fatalf("the list carried %q", creds[len(creds)-1])
	}

	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Legacy = true })
	if tools, err := r.c.Tools(ctx, noted); err != nil || len(tools) != len(stubs.ConnectorTools) || r.mcp.Sessions() != 0 {
		t.Fatalf("an earlier revision: %+v %v, %d sessions", tools, err, r.mcp.Sessions())
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Paged = true })
	if tools, err := r.c.Tools(ctx, noted); err != nil || len(tools) != len(stubs.ConnectorTools) || tools[4].Name != stubs.ConnectorTools[4] {
		t.Fatalf("an earlier revision's pages: %+v %v", tools, err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Legacy = false })
	if tools, err := r.c.Tools(ctx, noted); err != nil || len(tools) != len(stubs.ConnectorTools) {
		t.Fatalf("pages: %+v %v", tools, err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })

	// A signed-in connection's refused token is refreshed once and the list
	// asked again with the new one.
	signed, access := r.signedInTo("notes-signed", "alice", time.Now().Add(time.Hour))
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse = []string{"Bearer " + access} })
	if tools, err := r.c.Tools(ctx, signed); err != nil || len(tools) == 0 {
		t.Fatalf("a refreshed list: %+v %v", tools, err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll = true })
	if _, err := r.c.Tools(ctx, signed); apierr.Classify(err).Reason != store.ReasonRevoked {
		t.Fatalf("a list refused twice: %v", err)
	}
	minted := r.connect("alice", "notes-minted", store.Secrets{ClientSecret: "a-minted-client-secret"}, store.Meta{
		ClientID: "pons-client", TokenEndpoint: r.auth.TokenURL(), Scopes: []string{"read"},
	})
	r.auth.AddClient("pons-client", "a-minted-client-secret")
	if _, err := r.c.Tools(ctx, minted); apierr.Classify(err).Reason != store.ReasonCredentialRefused {
		t.Fatalf("a minted token refused twice: %v", err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{Slow: 0, Redirect: true} })
	open := r.connect("alice", "notes-open", store.Secrets{}, store.Meta{})
	if _, err := r.c.Tools(ctx, open); apierr.Classify(err).Code != apierr.CodeConnectorUnavailable {
		t.Fatalf("a redirect: %v", err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
	if tools, err := r.c.Tools(ctx, open); err != nil || len(tools) == 0 {
		t.Fatalf("an open connection: %+v %v", tools, err)
	}

	// A connection of kind http, one whose connector left, one turned off
	// and one that cannot reach its server have no list.
	if _, err := r.c.Tools(ctx, r.keyed()); apierr.Classify(err).Code != apierr.CodeWrongKind {
		t.Fatalf("kind http: %v", err)
	}
	gone := noted
	gone.Connector = "nothing"
	if _, err := r.c.Tools(ctx, gone); apierr.Classify(err).Reason != "connector_removed" {
		t.Fatalf("a connector that left: %v", err)
	}
	off := r.conns["notes"]
	off.Disabled = true
	r.conns["notes"] = off
	if _, err := r.c.Tools(ctx, noted); apierr.Classify(err).Reason != "connector_disabled" {
		t.Fatalf("a connector turned off: %v", err)
	}
	off.Disabled, off.URL = false, "https://nobody.example.com/mcp"
	r.conns["notes"] = off
	if _, err := r.c.Tools(ctx, noted); apierr.Classify(err).Code != apierr.CodeConnectorUnavailable {
		t.Fatalf("a server that cannot be reached: %v", err)
	}
	off.URL = "https://%zz"
	r.conns["notes"] = off
	if _, err := r.c.Tools(ctx, noted); apierr.Classify(err).Code != apierr.CodeConnectorUnavailable {
		t.Fatalf("an address that builds no request: %v", err)
	}
}
