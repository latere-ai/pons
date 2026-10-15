// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

// Through the front, a stub is reached at port 443 by the name its
// handshake names, and at its own port as asked; a name no route names is
// a connection that fails, and the stub's metadata names the address it
// was reached at.
func TestTheFrontReachesStubsAtPort443(t *testing.T) {
	c := stubs.NewConnector(t)
	other := stubs.NewConnector(t, stubs.WithConnectorName("tools.example.com"))
	front := stubs.NewFront(t, (&net.Dialer{}).DialContext)
	front.Route(c.Name(), c.Port())
	front.Route(other.Name(), other.Port())
	client := dial.New(dial.Options{
		Resolver: stubs.Resolver(), Roots: stubs.Roots(), Proxy: front.URL(),
		Permit: stubs.Permit(443, c.Port(), other.Port()),
	})
	// A request that names no protocol version is answered by the stub's
	// JSON-RPC error, which only the stub sends.
	if _, _, body := send(t, client, http.MethodPost, "https://mcp.example.com/mcp", "", nil); !strings.Contains(string(body), "jsonrpc") || len(c.Requests()) != 1 {
		t.Fatalf("at port 443: %s", body)
	}
	if _, _, body := send(t, client, http.MethodPost, c.URL(), "", nil); !strings.Contains(string(body), "jsonrpc") || len(c.Requests()) != 2 {
		t.Fatalf("at its own port: %s", body)
	}
	if _, _, body := send(t, client, http.MethodPost, "https://tools.example.com/mcp", "", nil); !strings.Contains(string(body), "jsonrpc") || len(other.Requests()) != 1 {
		t.Fatalf("the second stub: %s %d", body, len(other.Requests()))
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://nobody.example.com/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(t.Context(), dial.Request{HTTP: req}); err == nil {
		t.Fatal("a name no route names was reached")
	}
	closed := dial.New(dial.Options{
		Resolver: stubs.Resolver(), Roots: stubs.Roots(), Proxy: stubs.NewFront(t, refuse).URL(),
		Permit: stubs.Permit(443, c.Port()),
	})
	req, err = http.NewRequestWithContext(t.Context(), http.MethodPost, c.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closed.Do(t.Context(), dial.Request{HTTP: req}); err == nil {
		t.Fatal("a tunnel the front could not open was reached")
	}
	c.Set(func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{"https://auth.example.com"} })
	answer, err := client.Fetch(t.Context(), "https://mcp.example.com/.well-known/oauth-protected-resource/mcp", nil)
	if err != nil || !strings.Contains(string(answer.Body), `"resource":"https://mcp.example.com/mcp"`) {
		t.Fatalf("the metadata at port 443: %v %s", err, answer.Body)
	}
}

// refuse is a dial that opens nothing.
func refuse(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("refused")
}
