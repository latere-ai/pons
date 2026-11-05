// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stub serves what a healthy ponsd serves under its base path: the contract
// with no token, and a refusal of the authenticated surface.
func stub(t *testing.T, contract string) *httptest.Server {
	return stubVersion(t, contract, served)
}

// served is a version route that serves the build v1.2.3.
func served(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"version":"v1.2.3","commit":"abc1234","build_time":"2026-11-05T00:00:00Z"}` + "\n"))
}

// stubVersion is stub with the version route a test chooses; nil leaves it
// unserved.
func stubVersion(t *testing.T, contract string, version http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if version != nil {
		mux.HandleFunc("GET /v1/connections/version", version)
	}
	mux.HandleFunc("GET /v1/connections/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(contract))
	})
	mux.HandleFunc("GET /v1/connections/connections", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"missing_token"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const contract = "openapi: 3.1.0\ninfo:\n  title: Pons\n  version: \"1\"\n"

func script(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "release.sh")
}

// run executes the script and returns its combined output and whether it
// exited zero. It skips when a tool the script needs is not on PATH, as the
// gate's hermetic run holds only the Go toolchain.
func run(t *testing.T, env ...string) (string, bool) {
	t.Helper()
	for _, cmd := range []string{"bash", "curl", "grep", "mktemp"} {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Skipf("%s is not on PATH, so release.sh cannot run here", cmd)
		}
	}
	cmd := exec.CommandContext(context.Background(), "bash", script(t))
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func TestSmokePassesAgainstAHealthyService(t *testing.T) {
	srv := stub(t, contract)
	evidence := filepath.Join(t.TempDir(), "smoke.md")
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections", "TAG=v1.2.3", "COMMIT=abc1234", "OUTPUT_MD="+evidence)
	if !ok {
		t.Fatalf("the smoke failed against a healthy service:\n%s", out)
	}
	md, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Release evidence", "- Tag: `v1.2.3`", "- Commit: `abc1234`", "Served version: `v1.2.3`, equal to the tag"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("the evidence lacks %q:\n%s", want, md)
		}
	}
}

func TestSmokeFailsWhenTheServedVersionIsNotTheTag(t *testing.T) {
	srv := stub(t, contract)
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections", "TAG=v1.2.4")
	if ok || !strings.Contains(out, "version mismatch: served v1.2.3, expected v1.2.4") {
		t.Fatalf("the smoke passed or did not name both versions (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeRecordsTheVersionWithNoTag(t *testing.T) {
	srv := stub(t, contract)
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections")
	if !ok || !strings.Contains(out, "served version recorded (v1.2.3)") {
		t.Fatalf("want a pass that records the version (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeFailsWhenTheVersionRouteIsNotServed(t *testing.T) {
	srv := stubVersion(t, contract, nil)
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections", "TAG=v1.2.3")
	if ok || !strings.Contains(out, "GET /version: expected 200, got 404") {
		t.Fatalf("the smoke passed or did not name the route (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeFailsOnAWrongContract(t *testing.T) {
	srv := stub(t, "openapi: 3.1.0\ninfo:\n  title: Other\n")
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections")
	if ok || !strings.Contains(out, "not the Pons contract") {
		t.Fatalf("the smoke passed or did not name the contract (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeFailsWhenTheServiceIsDown(t *testing.T) {
	srv := stub(t, contract)
	url := srv.URL
	srv.Close()
	out, ok := run(t, "BASE_URL="+url+"/v1/connections", "TAG=v1.2.3")
	if ok {
		t.Fatalf("the smoke passed against a service that is down:\n%s", out)
	}
	if !strings.Contains(out, "curl failed") {
		t.Errorf("the failure does not say the service did not answer:\n%s", out)
	}
}

func TestSmokeFailsWhenTheBasePathIsNotRouted(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	out, ok := run(t, "BASE_URL="+srv.URL+"/v1/connections")
	if ok || !strings.Contains(out, "expected 200, got 404") {
		t.Fatalf("the smoke passed or did not name the status (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeRefusesWithNoTarget(t *testing.T) {
	out, ok := run(t, "BASE_URL=")
	if ok || !strings.Contains(out, "BASE_URL is required") {
		t.Fatalf("the smoke ran with no target (ok=%v):\n%s", ok, out)
	}
}
