// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/store"
)

// The git address serves the four smart HTTP requests and answers every
// other path 404.
func TestTheGitAddressServesGitAlone(t *testing.T) {
	r := newRig(t, true)
	c := r.keyed()
	git := address(c, "git")
	for _, ok := range []struct{ method, path string }{
		{http.MethodGet, "/acme/app.git/info/refs?service=git-upload-pack"},
		{http.MethodGet, "/acme/app.git/info/refs?service=git-receive-pack"},
		{http.MethodPost, "/acme/app.git/git-upload-pack"},
	} {
		if a := r.send(ok.method, git+ok.path, "alice", strings.NewReader("0000"), "Content-Type", "application/x-git-upload-pack-request"); a.status != http.StatusOK {
			t.Errorf("%s %s: %d %s", ok.method, ok.path, a.status, a.body)
		}
	}
	before := len(r.git.Requests())
	for _, bad := range []struct{ method, path string }{
		{http.MethodGet, "/acme/app.git"},
		{http.MethodGet, "/acme/app.git/info/refs"},
		{http.MethodGet, "/acme/app.git/info/refs?service=git-upload-archive"},
		{http.MethodPost, "/acme/app.git/info/refs?service=git-upload-pack"},
		{http.MethodGet, "/acme/app.git/git-upload-pack"},
		{http.MethodGet, "/acme/app.git/HEAD"},
		{http.MethodGet, "/acme/app.git/objects/info/packs"},
		{http.MethodPut, "/acme/app.git/git-receive-pack"},
	} {
		if a := r.send(bad.method, git+bad.path, "alice", nil); a.status != http.StatusNotFound || a.code() != "connection_not_found" {
			t.Errorf("%s %s: %d %s", bad.method, bad.path, a.status, a.body)
		}
	}
	if got := len(r.git.Requests()); got != before {
		t.Fatalf("%d requests that are not git's reached the git host", got-before)
	}
	for _, rq := range r.git.Requests() {
		if rq.Credential != "Basic eC1hY2Nlc3MtdG9rZW46dGhlLWtleS1vZi1hbGljZS0wMDAx" {
			t.Fatalf("the git host saw %q", rq.Credential)
		}
	}
	// A connection of kind mcp has no git address, nor one whose connector
	// names no git host.
	tools := r.connect("alice", "tools", store.Secrets{}, store.Meta{})
	if a := r.send(http.MethodGet, address(tools, "git")+"/acme/app.git/info/refs?service=git-upload-pack", "alice", nil); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("an mcp connection's git address: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(tools, "http")+"/user", "alice", nil); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("an mcp connection's forwarding address: %d %s", a.status, a.body)
	}
	open := r.connect("alice", "open", store.Secrets{}, store.Meta{})
	if a := r.send(http.MethodGet, address(open, "git")+"/acme/app.git/info/refs?service=git-upload-pack", "alice", nil); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("a connector with no git host: %d %s", a.status, a.body)
	}
}

// pkt is one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const zero = "0000000000000000000000000000000000000000"

// A push naming a ref outside Refs is refused before any of the pack is
// sent, a push inside it lands, a deletion is held to the same rule, and a
// compressed push is refused.
func TestAPushIsHeldToItsRefs(t *testing.T) {
	r := newRig(t, true)
	c := r.keyed()
	r.az.set(authorizer.Limits{Refs: []string{"refs/heads/agents/*"}})
	remote := r.srv.URL + address(c, "git") + "/acme/app.git"
	dir := t.TempDir()
	if out, err := gitRun(t, dir, "alice", "clone", "--quiet", remote, "app"); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	work := filepath.Join(dir, "app")
	if err := os.WriteFile(filepath.Join(work, "CHANGE"), []byte("a change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "CHANGE"}, {"commit", "--quiet", "-m", "change"}} {
		if out, err := gitRun(t, work, "alice", args...); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	before := r.git.Requests()
	out, err := gitRun(t, work, "alice", "push", "origin", "HEAD:refs/heads/main")
	if err == nil || !strings.Contains(out, "403") {
		t.Fatalf("a push to main: %v %s", err, out)
	}
	for _, rq := range r.git.Requests()[len(before):] {
		if strings.HasSuffix(rq.Path, "/git-receive-pack") {
			t.Fatal("a push outside the refs reached the git host")
		}
	}
	if out, err := gitRun(t, work, "alice", "push", "--quiet", "origin", "HEAD:refs/heads/agents/one"); err != nil {
		t.Fatalf("a push to the session's branch: %v %s", err, out)
	}
	refs, err := r.git.Refs("acme/app.git")
	if err != nil || refs["refs/heads/agents/one"] == "" {
		t.Fatalf("the branch did not land: %v %v", refs, err)
	}
	if out, err := gitRun(t, work, "alice", "push", "origin", ":refs/heads/main"); err == nil {
		t.Fatalf("a deletion of main: %s", out)
	}
	if out, err := gitRun(t, work, "alice", "push", "--quiet", "origin", ":refs/heads/agents/one"); err != nil {
		t.Fatalf("a deletion of the session's branch: %v %s", err, out)
	}
	if refs, err := r.git.Refs("acme/app.git"); err != nil || refs["refs/heads/agents/one"] != "" || refs["refs/heads/main"] == "" {
		t.Fatalf("after the deletions: %v %v", refs, err)
	}
	var pushes []store.Call
	for _, rec := range r.calls(c) {
		if rec.Tool == ReceivePack && rec.Method == http.MethodPost {
			pushes = append(pushes, rec)
		}
	}
	// The second denied push of the minute is counted and not recorded.
	if len(pushes) != 3 || pushes[0].Refs != 1 || pushes[0].Outcome != OutcomeDenied || pushes[1].Outcome != OutcomeOK || pushes[1].Effect != "write" {
		t.Fatalf("the pushes' records %+v", pushes)
	}

	push := address(c, "git") + "/acme/app.git/git-receive-pack"
	if a := r.send(http.MethodPost, push, "alice", strings.NewReader(pkt(zero+" "+strings.Repeat("1", 40)+" refs/heads/agents/x\x00report-status\n")+"0000"), "Content-Encoding", "gzip"); a.status != http.StatusBadRequest || a.detail("field") != "Content-Encoding" {
		t.Fatalf("a compressed push: %d %s", a.status, a.body)
	}
	many := strings.Builder{}
	for i := range MaxCommands + 1 {
		many.WriteString(pkt(fmt.Sprintf("%s %s refs/heads/agents/%d\n", zero, strings.Repeat("1", 40), i)))
	}
	many.WriteString("0000")
	for name, body := range map[string]string{
		"no flush":         pkt(zero + " " + strings.Repeat("1", 40) + " refs/heads/agents/x\n"),
		"no command":       pkt("shallow "+strings.Repeat("2", 40)+"\n") + "0000",
		"a flush and more": "0000PACK",
		"a bad length":     "zzzz",
		"a short line":     "0004",
		"a bad id":         pkt("xyz "+strings.Repeat("1", 40)+" refs/heads/agents/x\n") + "0000",
		"ids of two sizes": pkt(zero+" "+strings.Repeat("1", 64)+" refs/heads/agents/x\n") + "0000",
		"not a ref":        pkt(zero+" "+strings.Repeat("1", 40)+" HEAD\n") + "0000",
		"a bad shallow":    pkt("shallow xyz\n") + "0000",
		"past the count":   many.String(),
		"past the size":    pkt(zero+" "+strings.Repeat("1", 40)+" refs/heads/agents/"+strings.Repeat("x", 40000)+"\n") + pkt(zero+" "+strings.Repeat("1", 40)+" refs/heads/agents/"+strings.Repeat("y", 40000)+"\n") + "0000",
	} {
		if a := r.send(http.MethodPost, push, "alice", strings.NewReader(body)); a.status != http.StatusBadRequest || a.detail("reason") != "push_commands" {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	// A shallow line before the commands names no ref.
	cmds, read, err := readCommands(strings.NewReader(pkt("shallow "+strings.Repeat("2", 40)+"\n") + pkt(zero+" "+strings.Repeat("1", 40)+" refs/heads/agents/x\x00caps\n") + "0000PACK"))
	if err != nil || len(cmds) != 1 || cmds[0].Ref != "refs/heads/agents/x" || !bytes.HasSuffix(read, []byte("0000")) {
		t.Fatalf("a shallow push: %+v %v", cmds, err)
	}
}

// A push larger than git's post buffer begins with git's probe, a flush-pkt
// alone, which names no ref and is forwarded; the push after it lands.
func TestALargePushPassesGitsProbe(t *testing.T) {
	r := newRig(t, true)
	c := r.keyed()
	r.az.set(authorizer.Limits{Refs: []string{"refs/heads/agents/*"}})
	push := address(c, "git") + "/acme/app.git/git-receive-pack"
	if a := r.send(http.MethodPost, push, "alice", strings.NewReader("0000"), "Content-Type", "application/x-git-receive-pack-request"); a.status != http.StatusOK {
		t.Fatalf("git's probe: %d %s", a.status, a.body)
	}
	work := cloneWithChange(t, r, c, 200<<10)
	// The smallest post buffer git takes, so the push is a large one.
	if out, err := gitRun(t, work, "alice", "-c", "http.postBuffer=65520", "push", "--quiet", "origin", "HEAD:refs/heads/agents/large"); err != nil {
		t.Fatalf("a large push: %v %s", err, out)
	}
	if refs, err := r.git.Refs("acme/app.git"); err != nil || refs["refs/heads/agents/large"] == "" {
		t.Fatalf("the branch did not land: %v %v", refs, err)
	}
}

// cloneWithChange clones the stub's repository through the git address and
// commits a file of size random bytes, which no pack compresses, answering
// the working tree.
func cloneWithChange(t *testing.T, r *rig, c store.Connection, size int) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := gitRun(t, dir, "alice", "clone", "--quiet", r.srv.URL+address(c, "git")+"/acme/app.git", "app"); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	work := filepath.Join(dir, "app")
	change := make([]byte, size)
	if _, err := rand.Read(change); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "CHANGE"), change, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "CHANGE"}, {"commit", "--quiet", "-m", "change"}} {
		if out, err := gitRun(t, work, "alice", args...); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	return work
}
