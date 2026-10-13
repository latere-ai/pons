// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pgtest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"latere.ai/x/ci-gate/reap"
)

// errStop is what every run of the stand-in engine answers, so a start goes
// no further than the container it asked for.
var errStop = errors.New("the stand-in engine starts nothing")

// engine stands in for the container engine for one test. It records each
// call in order, as sweep, network, or the image a run asked for, and holds
// every container request to the labels reap gives this process.
func engine(t *testing.T) *[]string {
	t.Helper()
	// A DOCKER_HOST that resolves nowhere leaves the reaper as it is, and a
	// run label makes the labels two.
	t.Setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
	t.Setenv("LATEREGATE_RUN", "pgtest-run")
	prevSweep, prevNetwork, prevPostgres, prevContainer := sweep, newNetwork, runPostgres, runContainer
	t.Cleanup(func() {
		sweep, newNetwork, runPostgres, runContainer = prevSweep, prevNetwork, prevPostgres, prevContainer
		// What the stand-in returned is nothing Stop can remove.
		mu.Lock()
		containers, shared = nil, nil
		mu.Unlock()
	})
	var calls []string
	labeled := func(image string, opts []testcontainers.ContainerCustomizer) {
		req := testcontainers.GenericContainerRequest{}
		for _, o := range opts {
			if err := o.Customize(&req); err != nil {
				t.Fatal(err)
			}
		}
		want := reap.Labels()
		if len(want) != 2 {
			t.Fatalf("reap.Labels() = %v, want the owner and the run", want)
		}
		for k, v := range want {
			if req.Labels[k] != v {
				t.Errorf("%s: the label %s = %q, want %q", image, k, req.Labels[k], v)
			}
		}
		calls = append(calls, image)
	}
	sweep = func(context.Context) (int, error) {
		calls = append(calls, "sweep")
		return 0, nil
	}
	newNetwork = func(_ context.Context, labels map[string]string) (*testcontainers.DockerNetwork, error) {
		for k, v := range reap.Labels() {
			if labels[k] != v {
				t.Errorf("the network's label %s = %q, want %q", k, labels[k], v)
			}
		}
		calls = append(calls, "network")
		return &testcontainers.DockerNetwork{Name: "pgtest-network"}, nil
	}
	runPostgres = func(_ context.Context, image string, opts ...testcontainers.ContainerCustomizer) (*tcpostgres.PostgresContainer, error) {
		labeled(image, opts)
		return nil, errStop
	}
	runContainer = func(_ context.Context, image string, opts ...testcontainers.ContainerCustomizer) (*testcontainers.DockerContainer, error) {
		labeled(image, opts)
		return nil, errStop
	}
	return &calls
}

// A start removes what exited binaries left before it makes anything of its
// own, and labels the server so the next start, and the gate, can find it
// if this binary dies before Stop.
func TestAStartSweepsThenLabelsTheServer(t *testing.T) {
	calls := engine(t)
	if _, err := start(context.Background()); !errors.Is(err, errStop) {
		t.Fatalf("start = %v, want the stand-in's refusal", err)
	}
	if want := []string{"sweep", "network", postgresImage}; !slices.Equal(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
}

// The pooler is labeled as the server is: a container left unlabeled is
// one no sweep removes.
func TestThePoolerIsLabeled(t *testing.T) {
	calls := engine(t)
	if _, err := startPooler(context.Background(), &testcontainers.DockerNetwork{Name: "pgtest-network"}); !errors.Is(err, errStop) {
		t.Fatalf("startPooler = %v, want the stand-in's refusal", err)
	}
	if want := []string{poolerImage}; !slices.Equal(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
}

// A DOCKER_HOST that names Podman's socket turns the reaper off, whatever
// the fallback socket is. Before DOCKER_HOST was read, only the fallback
// was looked at, and a Podman machine reached through DOCKER_HOST alone
// kept a reaper that cannot start, which failed every start.
func TestADockerHostOnPodmanTurnsTheReaperOff(t *testing.T) {
	dir := t.TempDir()
	machine := filepath.Join(dir, "podman", "machine", "podman.sock")
	docker := filepath.Join(dir, "docker", "docker.sock")
	for _, p := range []string{machine, docker} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "docker.sock")
	if err := os.Symlink(machine, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, dockerHost, fallback, want string
	}{
		{"DOCKER_HOST on Podman", "unix://" + machine, docker, "true"},
		{"DOCKER_HOST on Docker, a fallback on Podman", "unix://" + docker, link, ""},
		{"DOCKER_HOST over TCP", "tcp://127.0.0.1:2375", link, ""},
		{"no DOCKER_HOST, a fallback linked to Podman", "", link, "true"},
		{"no DOCKER_HOST, a fallback of Docker's own", "", docker, ""},
		{"no DOCKER_HOST, no fallback", "", filepath.Join(dir, "absent.sock"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "")
			reaper(c.dockerHost, c.fallback)
			if got := os.Getenv("TESTCONTAINERS_RYUK_DISABLED"); got != c.want {
				t.Fatalf("TESTCONTAINERS_RYUK_DISABLED = %q, want %q", got, c.want)
			}
		})
	}
}

// A start that made no container keeps nothing for Stop. A nil server kept
// as a container made Stop panic before it removed the network.
func TestAStartThatMadeNoContainerKeepsNothing(t *testing.T) {
	engine(t)
	ctx := context.Background()
	_, _ = start(ctx)
	_, _ = startPooler(ctx, &testcontainers.DockerNetwork{Name: "pgtest-network"})
	mu.Lock()
	n := len(containers)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("kept %d containers from starts that made none", n)
	}
}
