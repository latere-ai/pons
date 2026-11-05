// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// benchToolsAnswer builds an answer to tools/list with n tools, each with
// a description and an input schema the way a server lists them.
func benchToolsAnswer(tb testing.TB, n int) []byte {
	tb.Helper()
	tools := make([]map[string]any, n)
	for i := range tools {
		tools[i] = map[string]any{
			"name":        fmt.Sprintf("repo_tool_%03d", i),
			"description": "Reads or changes a resource in the repository and answers with the result. " + strings.Repeat("Details of the arguments. ", 3),
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Path below the repository root."},
					"ref":   map[string]any{"type": "string", "description": "Branch, tag or commit."},
					"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
				},
				"required": []string{"path"},
			},
			"annotations": map[string]any{"readOnlyHint": i%2 == 0, "idempotentHint": true},
		}
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  map[string]any{"tools": tools, "nextCursor": "page-2-cursor"},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

var benchListSizes = []struct {
	name  string
	tools int
}{
	{"small", 1},
	{"medium", 19},
	{"large", 390},
}

// BenchmarkJSONToolsListUnmarshal is ToolsOf on a JSON answer to tools/list,
// read for every page of a connection's tools.
func BenchmarkJSONToolsListUnmarshal(b *testing.B) {
	for _, s := range benchListSizes {
		b.Run(s.name, func(b *testing.B) {
			body := benchToolsAnswer(b, s.tools)
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				tools, next, err := ToolsOf("application/json", body)
				if err != nil {
					b.Fatal(err)
				}
				if len(tools) != s.tools || next == "" {
					b.Fatal("unexpected list")
				}
			}
		})
	}
}

// BenchmarkJSONToolsListEventStreamUnmarshal is ToolsOf on an answer
// delivered as an event stream.
func BenchmarkJSONToolsListEventStreamUnmarshal(b *testing.B) {
	for _, s := range benchListSizes {
		b.Run(s.name, func(b *testing.B) {
			msg := benchToolsAnswer(b, s.tools)
			body := []byte("event: message\ndata: " + string(msg) + "\n\n")
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				tools, _, err := ToolsOf("text/event-stream", body)
				if err != nil {
					b.Fatal(err)
				}
				if len(tools) != s.tools {
					b.Fatal("unexpected list")
				}
			}
		})
	}
}

// BenchmarkJSONListToolsRequestMarshal builds the probe's request of the
// current revision and the page after a cursor.
func BenchmarkJSONListToolsRequestMarshal(b *testing.B) {
	ctx := context.Background()
	req, err := ListToolsAfter(ctx, "https://mcp.example.com/mcp", "page-2-cursor")
	if err != nil {
		b.Fatal(err)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := ListToolsAfter(ctx, "https://mcp.example.com/mcp", "page-2-cursor"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJSONInitializeAnswerUnmarshal is Negotiated and ModernError on
// the answers of the handshake and of a refused probe.
func BenchmarkJSONInitializeAnswerUnmarshal(b *testing.B) {
	init := []byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true},"logging":{}},"serverInfo":{"name":"example","version":"1.4.2"}}}`)
	refusal := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"unsupported protocol version","data":{"supported":["2026-07-28"]}}}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(init) + len(refusal)))
	for b.Loop() {
		if Negotiated(init) != "2025-11-25" {
			b.Fatal("version not read")
		}
		if !ModernError(refusal) {
			b.Fatal("error not recognized")
		}
	}
}
