// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/test/stubs"
)

// git runs a git client against the server, with the caller's token in
// every request and nothing of the machine's configuration.
func git(t *testing.T, dir, token string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), gitBinary(t), append([]string{"-c", "http.extraHeader=Authorization: Bearer " + token}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "none"), "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Agent", "GIT_AUTHOR_EMAIL=agent@example.com", "GIT_COMMITTER_NAME=Agent", "GIT_COMMITTER_EMAIL=agent@example.com")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A clone and a fetch through the git address of a connection to the stub
// git host succeed with the credential placed as git.inject says, a push
// lands on a branch its allow names and not on another, and the caller's
// token never reaches the stub.
func TestCloneThroughTheGitAddress(t *testing.T) {
	if _, err := stubs.GitPath(); err != nil {
		t.Skip(err.Error())
	}
	iss := stubs.NewIssuer(t)
	az, over := withAuthorizer(t, nil, stub.WithAllow("*"))
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionUse, Limits: map[string]any{"refs": []string{"refs/heads/agents/*"}}})
	s := startStack(t, iss, over)
	up := upstreamOf(t)
	c := s.connect("alice", "forge", "", map[string]any{"value": "the-forge-key-of-alice"}).json(t)
	remote, _ := c["git_address"].(string)
	if !strings.HasSuffix(remote, "/connections/"+c["id"].(string)+"/git") {
		t.Fatalf("the git address %v", c["git_address"])
	}
	// The address is the public URL's; the server listens where the test
	// started it.
	remote = s.base + strings.TrimPrefix(remote, "http://127.0.0.1:8080") + "/acme/app.git"
	token := iss.Token("alice", map[string]any{"session": "ses_clone"})
	dir := t.TempDir()
	if out, err := git(t, dir, token, "clone", "--quiet", remote, "app"); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	work := filepath.Join(dir, "app")
	if out, err := git(t, work, token, "fetch", "--quiet", "origin"); err != nil {
		t.Fatalf("fetch: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(work, "CHANGE"), []byte("a change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "CHANGE"}, {"commit", "--quiet", "-m", "change"}} {
		if out, err := git(t, work, token, args...); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	if out, err := git(t, work, token, "push", "--quiet", "origin", "HEAD:refs/heads/agents/ses-clone"); err != nil {
		t.Fatalf("a push to the session's branch: %v %s", err, out)
	}
	if out, err := git(t, work, token, "push", "origin", "HEAD:refs/heads/main"); err == nil || !strings.Contains(out, "403") {
		t.Fatalf("a push to main: %v %s", err, out)
	}
	refs, err := up.git.Refs("acme/app.git")
	if err != nil || refs["refs/heads/agents/ses-clone"] == "" {
		t.Fatalf("the branch: %v %v", refs, err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:the-forge-key-of-alice"))
	for _, rq := range up.git.Requests() {
		if rq.Credential != basic {
			t.Fatalf("the git host saw %q", rq.Credential)
		}
	}
	if strings.Contains(s.everything(), "the-forge-key-of-alice") || strings.Contains(s.dump(), "the-forge-key-of-alice") {
		t.Fatal("the key left toward somewhere but its git host")
	}
	calls := s.do("GET", "/v1/connections/"+c["id"].(string)+"/calls?limit=200", "alice", nil).json(t)["items"].([]any)
	pushes, sessions := 0, 0
	for _, item := range calls {
		rec := item.(map[string]any)
		if rec["tool"] == "git-receive-pack" && rec["method"] == "POST" {
			pushes++
		}
		if rec["session"] == "ses_clone" {
			sessions++
		}
	}
	if pushes != 2 || sessions != len(calls) {
		t.Fatalf("the records %v", calls)
	}
}

// gitBinary is the git a test runs, or a skip with the reason.
func gitBinary(t *testing.T) string {
	t.Helper()
	path, err := stubs.GitPath()
	if err != nil {
		t.Skip(err.Error())
	}
	return path
}
