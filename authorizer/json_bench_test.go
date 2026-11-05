// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer_test

import (
	"testing"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
)

// BenchmarkJSONLimitsUnmarshal is DecodeLimits on the limits of an allow,
// read for every request Pons authorizes.
func BenchmarkJSONLimitsUnmarshal(b *testing.B) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ``},
		{"small", `{"read_only":true,"calls_per_minute":60}`},
		{"full", `{"owner":"user:7f3a9c","max_connections":20,"connectors":["github","linear","notion-*"],"read_only":false,"tools":["search_*","get_*","list_*","create_issue"],"refs":["refs/heads/agents/*","refs/tags/v*"],"requests":["GET /repos/*/issues","POST /repos/*/issues","GET /repos/*/pulls/**"],"calls_per_minute":120}`},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			d := authz.Decision{Limits: []byte(c.raw)}
			b.ReportAllocs()
			b.SetBytes(int64(len(c.raw)))
			for b.Loop() {
				if _, err := authorizer.DecodeLimits(d); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
