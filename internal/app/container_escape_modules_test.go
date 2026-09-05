package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/dockersocket"
)

func TestLaunchDockerSocketBreakoutWithStreamsPreservesShellInput(t *testing.T) {
	originalProbe := probeDockerSocket
	original := runDockerSocketBreakout
	t.Cleanup(func() {
		probeDockerSocket = originalProbe
		runDockerSocketBreakout = original
	})
	probeDockerSocket = func(_ context.Context, options dockersocket.Options) (dockersocket.Finding, error) {
		return dockersocket.Finding{
			SocketPath:      options.SocketPath,
			ServerVersion:   "test",
			OperatingSystem: "linux",
			Architecture:    "amd64",
			AvailableImages: []string{"peirates-test:latest"},
			Caveat:          "test daemon caveat",
		}, nil
	}

	var gotOptions dockersocket.Options
	var gotShellInput string
	runDockerSocketBreakout = func(_ context.Context, options dockersocket.Options) error {
		gotOptions = options
		remaining, err := io.ReadAll(options.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		gotShellInput = string(remaining)
		return nil
	}

	var stdout bytes.Buffer
	if err := launchDockerSocketBreakoutWithStreams(
		strings.NewReader("\npeirates-test:latest\nprintf marker\nexit\n"),
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if gotOptions.SocketPath != "/var/run/docker.sock" {
		t.Fatalf("socket path = %q", gotOptions.SocketPath)
	}
	if gotOptions.Image != "peirates-test:latest" {
		t.Fatalf("image = %q", gotOptions.Image)
	}
	if gotShellInput != "printf marker\nexit\n" {
		t.Fatalf("shell input = %q", gotShellInput)
	}
	if output := stdout.String(); !strings.Contains(output, "Docker socket path") ||
		!strings.Contains(output, "Existing image reference") ||
		!strings.Contains(output, "peirates-test:latest") ||
		!strings.Contains(output, "test daemon caveat") {
		t.Fatalf("prompts missing from output: %q", output)
	}
}

func TestLaunchDockerSocketBreakoutRequiresImage(t *testing.T) {
	originalProbe := probeDockerSocket
	original := runDockerSocketBreakout
	t.Cleanup(func() {
		probeDockerSocket = originalProbe
		runDockerSocketBreakout = original
	})
	probeDockerSocket = func(context.Context, dockersocket.Options) (dockersocket.Finding, error) {
		return dockersocket.Finding{}, nil
	}
	runDockerSocketBreakout = func(context.Context, dockersocket.Options) error {
		t.Fatal("launcher called without an image")
		return nil
	}

	err := launchDockerSocketBreakoutWithStreams(strings.NewReader("/run/docker.sock\n"), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "image reference is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestLaunchHostRootBreakoutWithStreamsUsesExplicitTarget(t *testing.T) {
	original := runHostRootBreakoutAt
	t.Cleanup(func() { runHostRootBreakoutAt = original })

	var gotTarget, gotShellInput string
	runHostRootBreakoutAt = func(target string, stdin io.Reader, _, _ io.Writer) error {
		gotTarget = target
		remaining, err := io.ReadAll(stdin)
		if err != nil {
			t.Fatal(err)
		}
		gotShellInput = string(remaining)
		return nil
	}

	if err := launchHostRootBreakoutWithStreams(
		strings.NewReader("/hostroot\nid\nexit\n"), io.Discard, io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if gotTarget != "/hostroot" {
		t.Fatalf("target = %q", gotTarget)
	}
	if gotShellInput != "id\nexit\n" {
		t.Fatalf("shell input = %q", gotShellInput)
	}
}

func TestLaunchHostRootBreakoutWithStreamsSupportsAutoDetection(t *testing.T) {
	original := runHostRootBreakout
	t.Cleanup(func() { runHostRootBreakout = original })

	called := false
	runHostRootBreakout = func(stdin io.Reader, _, _ io.Writer) error {
		called = true
		remaining, err := io.ReadAll(stdin)
		if err != nil {
			t.Fatal(err)
		}
		if string(remaining) != "exit\n" {
			t.Fatalf("shell input = %q", remaining)
		}
		return nil
	}

	if err := launchHostRootBreakoutWithStreams(strings.NewReader("\nexit\n"), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("auto-detect launcher was not called")
	}
}
