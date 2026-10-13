// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// GitHost is the stub git host: git's smart HTTP over bare repositories a
// test seeds, served by `git http-backend` under net/http/cgi, so a real git
// client clones, fetches and pushes through it. It records every request
// with the credential it carried. Its switch: Refuse answers 401 to every
// request.
type GitHost struct {
	url  string
	port int
	git  string // the git binary
	root string // the project root, where the bare repositories are
	home string // an empty home, so no configuration of the machine applies
	ctx  context.Context

	mu       sync.Mutex
	requests []GitRequest
	refuse   bool
}

// GitRequest is one request the stub git host served.
type GitRequest struct {
	Method string
	Path   string
	Query  string
	// Credential is the Authorization header the request carried.
	Credential string
	// ContentEncoding is the request's Content-Encoding.
	ContentEncoding string
}

// GitOption configures the stub git host.
type GitOption func(*gitConfig)

type gitConfig struct{ name string }

// WithGitName is the name the stub answers under, git.example.com by
// default.
func WithGitName(name string) GitOption { return func(c *gitConfig) { c.name = name } }

// gitPlaces are where git is installed on the systems a test runs on, read
// when the search path of a test's environment names none: a gate may run
// the suite with a path of its own toolchain alone.
var gitPlaces = []string{"/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"}

// GitPath is the git binary, or the reason a test that needs it is
// skipped: git is not installed.
func GitPath() (string, error) {
	path, err := exec.LookPath("git")
	if err == nil {
		return path, nil
	}
	for _, p := range gitPlaces {
		if info, serr := os.Stat(p); serr == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("git is not installed, and the stub git host serves through git http-backend: %w", err)
}

// NewGitHost starts a stub git host for the test, and skips the test with
// the reason when git is not installed.
func NewGitHost(t testing.TB, opts ...GitOption) *GitHost {
	t.Helper()
	path, err := GitPath()
	if err != nil {
		t.Skip(err.Error())
	}
	cfg := gitConfig{name: "git." + Domain}
	for _, o := range opts {
		o(&cfg)
	}
	g := &GitHost{git: path, root: t.TempDir(), home: t.TempDir(), ctx: t.Context()}
	backend := &cgi.Handler{
		Path: path, Args: []string{"http-backend"},
		Env: append(g.env(), "GIT_PROJECT_ROOT="+g.root, "GIT_HTTP_EXPORT_ALL=1"),
	}
	srv := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests = append(g.requests, GitRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Credential: r.Header.Get("Authorization"), ContentEncoding: r.Header.Get("Content-Encoding"),
		})
		refuse := g.refuse
		g.mu.Unlock()
		if refuse {
			w.Header().Set("WWW-Authenticate", `Basic realm="stub"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if r.ContentLength < 0 {
			// git sends a push larger than its post buffer chunked, which a
			// git host takes and CGI does not: the body is read whole here
			// and handed to the backend with its length.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "the request body did not read", http.StatusBadRequest)
				return
			}
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
		}
		backend.ServeHTTP(w, r)
	}), cfg.name)
	g.port = portOf(srv.URL)
	g.url = named(cfg.name, g.port)
	return g
}

// env is the environment every git the stub runs is given: an empty home
// and no system or global configuration, so nothing of the machine applies.
func (g *GitHost) env() []string {
	return []string{
		"HOME=" + g.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(g.home, "none"),
		"PATH=" + filepath.Dir(g.git),
	}
}

// URL is the git host's base, by its name: the value of a catalog entry's
// git.url.
func (g *GitHost) URL() string { return g.url }

// Port is the port the stub listens on.
func (g *GitHost) Port() int { return g.port }

// Refuse answers 401 to every request while on is true.
func (g *GitHost) Refuse(on bool) {
	g.mu.Lock()
	g.refuse = on
	g.mu.Unlock()
}

// Requests is every request served, in order.
func (g *GitHost) Requests() []GitRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]GitRequest(nil), g.requests...)
}

// Credentials is the credential every request carried, in order.
func (g *GitHost) Credentials() []string {
	var out []string
	for _, r := range g.Requests() {
		out = append(out, r.Credential)
	}
	return out
}

// Seed makes a bare repository at the path, such as "acme/app.git", that
// takes pushes, with one commit on main holding a README.
func (g *GitHost) Seed(repo string) error {
	bare := filepath.Join(g.root, filepath.FromSlash(repo))
	if _, err := os.Stat(bare); err == nil {
		return fmt.Errorf("stubs: the repository %s is seeded already", repo)
	}
	work, err := os.MkdirTemp(g.home, "seed")
	if err != nil {
		return err
	}
	if err := g.run(g.root, "init", "--quiet", "--bare", "-b", "main", bare); err != nil {
		return err
	}
	if err := g.run(bare, "config", "http.receivepack", "true"); err != nil {
		return err
	}
	if err := g.run(work, "init", "--quiet", "-b", "main", "."); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(work, "README"), []byte("seeded by the stub git host\n"), 0o600); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"add", "README"},
		{"-c", "user.name=Stub", "-c", "user.email=stub@" + Domain, "commit", "--quiet", "-m", "seed"},
		{"push", "--quiet", bare, "main"},
	} {
		if err := g.run(work, args...); err != nil {
			return err
		}
	}
	return nil
}

// Refs lists the refs of a seeded repository, each full name with its
// object id.
func (g *GitHost) Refs(repo string) (map[string]string, error) {
	cmd := exec.CommandContext(g.ctx, g.git, "for-each-ref", "--format=%(refname) %(objectname)")
	cmd.Dir = filepath.Join(g.root, filepath.FromSlash(repo))
	cmd.Env = g.env()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git for-each-ref: %w", err)
	}
	refs := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if name, id, ok := strings.Cut(line, " "); ok {
			refs[name] = id
		}
	}
	return refs, nil
}

// run runs git in a directory with the stub's environment.
func (g *GitHost) run(dir string, args ...string) error {
	cmd := exec.CommandContext(g.ctx, g.git, args...)
	cmd.Dir = dir
	cmd.Env = g.env()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, out.String())
	}
	return nil
}
