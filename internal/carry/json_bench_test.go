// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/mcp"
)

// benchToolsCallBody builds the body of a tools/call request whose
// arguments hold roughly size bytes of file content, the shape of a call
// that writes or edits a document.
func benchToolsCallBody(tb testing.TB, size int) []byte {
	tb.Helper()
	line := "func handle(w http.ResponseWriter, r *http.Request) { // fixed line of source text\n"
	content := strings.Repeat(line, size/len(line)+1)[:max(size-600, 1)]
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      42,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "repo_write_file",
			"arguments": map[string]any{
				"path":    "internal/server/handler.go",
				"content": content,
				"mode":    "overwrite",
			},
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"progressToken": "tok-7f3a9c",
			},
		},
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

var benchSizes = []struct {
	name string
	size int
}{
	{"small", 512},
	{"medium", 10 << 10},
	{"large", 200 << 10},
}

// BenchmarkJSONMCPMessageUnmarshal is the read of every POST to an MCP
// address: parseMessage and the mirrored-header comparison.
func BenchmarkJSONMCPMessageUnmarshal(b *testing.B) {
	for _, s := range benchSizes {
		b.Run(s.name, func(b *testing.B) {
			body := benchToolsCallBody(b, s.size)
			h := http.Header{}
			h.Set(mcp.HeaderMethod, "tools/call")
			h.Set(mcp.HeaderName, "repo_write_file")
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				m, why := parseMessage(body)
				if why != "" {
					b.Fatal(why)
				}
				if mirroredDiffers(h, m) {
					b.Fatal("mirrored headers differ")
				}
			}
		})
	}
}

// BenchmarkJSONMCPNotificationUnmarshal is parseMessage on a message with
// no params, the cheap and frequent case.
func BenchmarkJSONMCPNotificationUnmarshal(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, why := parseMessage(body); why != "" {
			b.Fatal(why)
		}
	}
}
