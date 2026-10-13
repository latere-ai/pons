// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	stderr, err := gitStderr(t, work, "alice", "push", "origin", "HEAD:refs/heads/main")
	if err == nil || !strings.Contains(stderr, " ! [remote rejected] HEAD -> main (only branches under refs/heads/agents/ may be pushed by this caller)") {
		t.Fatalf("a push to main: %v %s", err, stderr)
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
	head, err := readCommands(strings.NewReader(pkt("shallow "+strings.Repeat("2", 40)+"\n") + pkt(zero+" "+strings.Repeat("1", 40)+" refs/heads/agents/x\x00report-status side-band-64k\n") + "0000PACK"))
	if err != nil || len(head.commands) != 1 || head.commands[0].Ref != "refs/heads/agents/x" || !bytes.HasSuffix(head.read, []byte("0000")) ||
		!slices.Equal(head.caps, []string{"report-status", "side-band-64k"}) {
		t.Fatalf("a shallow push: %+v %v", head, err)
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

// A push Refs refuse is answered in git's own protocol, so git prints the
// reason and exits non-zero: 200 with a report-status in which every
// command is refused, in band 1 when the client asked for a side band, and
// an ERR packet to a client that asked for no report-status. The pack is
// read to its end first, so git reads the answer of a large push too, and
// nothing reaches the git host.
func TestARefusedPushSaysWhy(t *testing.T) {
	r := newRig(t, true)
	c := r.keyed()
	r.az.set(authorizer.Limits{Refs: []string{"refs/heads/agents/*"}})
	const rule = "only branches under refs/heads/agents/ may be pushed by this caller"
	push := address(c, "git") + "/acme/app.git/git-receive-pack"
	main := zero + " " + strings.Repeat("1", 40) + " refs/heads/main"
	mine := zero + " " + strings.Repeat("1", 40) + " refs/heads/agents/x"
	report := pkt("unpack ok\n") + pkt("ng refs/heads/main "+rule+"\n") + pkt("ng refs/heads/agents/x "+reasonWithTheRest+"\n") + "0000"
	for _, tc := range []struct{ name, caps, want string }{
		{"report-status", "report-status", report},
		{"report-status-v2 in band one", "report-status-v2 side-band-64k quiet", band(1, report) + "0000"},
		{"side-band in small packets", "report-status side-band", smallBands(report) + "0000"},
		{"no report-status", "quiet", pkt("ERR " + rule + "\n")},
		{"no report-status, a band", "side-band-64k", band(3, rule+"\n") + "0000"},
	} {
		name := tc.name
		before := len(r.git.Requests())
		body := pkt(main+"\x00"+tc.caps+"\n") + pkt(mine+"\n") + "0000PACK the pack"
		a := r.send(http.MethodPost, push, "alice", strings.NewReader(body), "Content-Type", "application/x-git-receive-pack-request")
		if a.status != http.StatusOK || a.header.Get("Content-Type") != "application/x-git-receive-pack-result" || string(a.body) != tc.want {
			t.Errorf("%s: %d %v %q", name, a.status, a.header, a.body)
		}
		if len(r.git.Requests()) != before {
			t.Errorf("%s: a refused push reached the git host", name)
		}
	}

	// A push larger than the server reads past on its own: without the pack
	// read to its end, git reads no answer and prints no reason.
	work := cloneWithChange(t, r, c, 600<<10)
	before := len(r.git.Requests())
	for _, args := range [][]string{
		{"push", "origin", "HEAD:refs/heads/main"},
		{"-c", "http.postBuffer=65520", "push", "origin", "HEAD:refs/heads/main"},
	} {
		stderr, err := gitStderr(t, work, "alice", args...)
		if err == nil || !strings.Contains(stderr, " ! [remote rejected] HEAD -> main ("+rule+")") {
			t.Errorf("a large push to main, %v: %v %s", args, err, stderr)
		}
	}
	// The one push that reached the git host is the second push's probe,
	// which names no ref.
	posts := 0
	for _, rq := range r.git.Requests()[before:] {
		if strings.HasSuffix(rq.Path, "/git-receive-pack") && rq.Method == http.MethodPost {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("%d pushes reached the git host", posts)
	}
	var denied []store.Call
	for _, rec := range r.calls(c) {
		if rec.Method == http.MethodPost && rec.Tool == ReceivePack {
			denied = append(denied, rec)
		}
	}
	// A denied push is recorded once a minute, and the probe as a push
	// that names no ref.
	if len(denied) != 2 || denied[0].Outcome != OutcomeDenied || denied[0].Status != 0 || denied[0].Refs != 2 ||
		denied[0].BytesIn != int64(len(pkt(main+"\x00report-status\n")+pkt(mine+"\n")+"0000PACK the pack")) ||
		denied[1].Outcome != OutcomeOK || denied[1].Refs != 0 {
		t.Fatalf("the records %+v", denied)
	}

	// A pack past the bound is 413, as a forwarded body is. The body names
	// no length, as a chunked push does, so the bound is found while the
	// pack is read and dropped.
	over := pkt(main+"\x00report-status\n") + "0000" + strings.Repeat("P", 1<<20)
	if a := r.send(http.MethodPost, push, "alice", io.MultiReader(strings.NewReader(over))); a.status != http.StatusRequestEntityTooLarge || a.detail("reason") != "max_forward_bytes=1048576" {
		t.Fatalf("a refused push past the bound: %d %s", a.status, a.body)
	}
}

// band is data in one band of side-band-64k.
func band(n byte, data string) string { return fmt.Sprintf("%04x", len(data)+5) + string(n) + data }

// smallBands is data in band 1 of side-band, in pkt-lines of at most 1000
// bytes.
func smallBands(data string) string {
	var out strings.Builder
	for len(data) > 0 {
		n := min(len(data), 995)
		out.WriteString(band(1, data[:n]))
		data = data[n:]
	}
	return out.String()
}

// The rule is one sentence built from Refs.
func TestTheRuleOfARefusedPush(t *testing.T) {
	for globs, want := range map[string]string{
		"refs/heads/agents/*":                           "only branches under refs/heads/agents/ may be pushed by this caller",
		"refs/heads/agents/*|refs/heads/users/*":        "only branches under refs/heads/agents/ or refs/heads/users/ may be pushed by this caller",
		"refs/heads/a/*|refs/heads/b/*|refs/heads/c/*":  "only branches under refs/heads/a/, refs/heads/b/, or refs/heads/c/ may be pushed by this caller",
		"refs/heads/agents/*|refs/tags/v*":              "only refs matching refs/heads/agents/* or refs/tags/v* may be pushed by this caller",
		"refs/heads/agent-*":                            "only refs matching refs/heads/agent-* may be pushed by this caller",
		"refs/heads/*/x/*":                              "only refs matching refs/heads/*/x/* may be pushed by this caller",
		"refs/heads/main":                               "only refs matching refs/heads/main may be pushed by this caller",
		"refs/heads/\nevil/*":                           reasonGeneral,
		"refs/heads/" + strings.Repeat("x", 300) + "/*": reasonGeneral,
		"": reasonGeneral,
	} {
		var refs []string
		if globs != "" {
			refs = strings.Split(globs, "|")
		}
		if got := refsRule(refs); got != want {
			t.Errorf("%q: %q, want %q", globs, got, want)
		}
	}
	// A report longer than one pkt-line of side-band-64k is split across
	// several.
	long := pushHead{caps: []string{"report-status", "side-band-64k"}}
	for i := range 1000 {
		long.commands = append(long.commands, command{Ref: fmt.Sprintf("refs/heads/main-%04d", i)})
	}
	got := long.refusal(authorizer.Limits{Refs: []string{"refs/heads/agents/*"}})
	var report bytes.Buffer
	for rest := got; ; {
		n, err := strconv.ParseUint(string(rest[:4]), 16, 32)
		if err != nil || n > maxPkt {
			t.Fatalf("a pkt-line of %d bytes: %v", n, err)
		}
		if n == 0 {
			break
		}
		if rest[4] != bandData {
			t.Fatalf("band %d", rest[4])
		}
		report.Write(rest[5:n])
		rest = rest[n:]
	}
	if c := strings.Count(report.String(), "ng refs/heads/main-"); c != 1000 || report.Len() <= maxPkt {
		t.Fatalf("%d refusals in %d bytes", c, report.Len())
	}
}
