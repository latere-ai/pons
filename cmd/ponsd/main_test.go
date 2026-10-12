// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/version"
)

// `ponsd version` prints the version, the commit and the date the build
// stamped.
func TestVersionIsStamped(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "ponsd")
	pkg := "latere.ai/x/pons/internal/version"
	build := exec.Command("go", "build", "-o", bin, "-ldflags",
		"-X "+pkg+".Version=v9.8.7 -X "+pkg+".Commit=c0ffee1 -X "+pkg+".Date=2026-10-12T00:00:00Z", ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), "ponsd v9.8.7 (c0ffee1, 2026-10-12T00:00:00Z)"; got != want {
		t.Fatalf("ponsd version printed %q, want %q", got, want)
	}
}

// The command line names one command and no flag.
func TestOneCommandAndNoFlag(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"version"}, func(string) string { return "" }, &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), version.String()) {
		t.Fatalf("version printed %q", out.String())
	}
	for _, args := range [][]string{nil, {"serve", "--addr=:1"}, {"-version"}, {"start"}} {
		err := run(context.Background(), args, func(string) string { return "" }, &out, &out)
		if err == nil || !strings.Contains(err.Error(), "one command") {
			t.Errorf("run(%q) = %v", args, err)
		}
	}
}
