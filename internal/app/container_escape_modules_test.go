package app

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/dockersocket"
)

func TestLaunchDockerSocketBreakoutWithStreamsPreservesShellInput(t *testing.T) {
	originalProbe := probeDockerSocket
	original := runDockerSocketBreakout
	originalFind := findAvailableDockerSocketPaths
	originalCanComplete := canCompleteDockerImagePrompt
	originalCompletionLine := readDockerImageCompletionLine
	t.Cleanup(func() {
		probeDockerSocket = originalProbe
		runDockerSocketBreakout = original
		findAvailableDockerSocketPaths = originalFind
		canCompleteDockerImagePrompt = originalCanComplete
		readDockerImageCompletionLine = originalCompletionLine
	})
	canCompleteDockerImagePrompt = func(io.Reader, io.Writer, io.Writer) bool { return false }
	readDockerImageCompletionLine = func(io.Reader, io.Writer, io.Writer, []string) (string, error) {
		t.Fatal("piped input used interactive image completion")
		return "", nil
	}
	findAvailableDockerSocketPaths = func() []string {
		return []string{"/run/docker.sock", "/var/run/docker.sock"}
	}
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
	output := stdout.String()
	wantPrefix := "Available Docker socket paths:\n- /run/docker.sock\n- /var/run/docker.sock\n" +
		"Docker socket path [/var/run/docker.sock]: "
	if !strings.HasPrefix(output, wantPrefix) ||
		!strings.Contains(output, "Existing image reference") ||
		!strings.Contains(output, "peirates-test:latest") ||
		!strings.Contains(output, "test daemon caveat") {
		t.Fatalf("prompts missing from output: %q", output)
	}
}

func TestDockerImageCompletionCandidatesAreSortedAndUnique(t *testing.T) {
	images := []string{"registry.example/team/tool:v2", "", "alpine:3.20", "registry.example/team/tool:v2", "busybox:latest"}
	want := []string{"alpine:3.20", "busybox:latest", "registry.example/team/tool:v2"}
	if got := dockerImageCompletionCandidates(images); !reflect.DeepEqual(got, want) {
		t.Fatalf("dockerImageCompletionCandidates() = %#v, want %#v", got, want)
	}
}

func TestDockerImageCompletionOffersOnlyDiscoveredImages(t *testing.T) {
	completer := setUpDockerImageCompletion([]string{
		"registry.example/team/tool:v2",
		"alpine:latest",
		"registry.example/team/tool:v2",
	})
	gotNames := make([]string, 0, len(completer.Children))
	for _, child := range completer.Children {
		gotNames = append(gotNames, child.Name)
	}
	wantNames := []string{"alpine:latest ", "registry.example/team/tool:v2 "}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("completion names = %#v, want %#v", gotNames, wantNames)
	}

	line := []rune("registry.example/team/t")
	got, offset := completer.Do(line, len(line))
	want := [][]rune{[]rune("ool:v2 ")}
	if !reflect.DeepEqual(got, want) || offset != len(line) {
		t.Fatalf("completion = %#v, offset %d; want %#v, offset %d", got, offset, want, len(line))
	}

	if got, _ := completer.Do([]rune("ubuntu"), len("ubuntu")); len(got) != 0 {
		t.Fatalf("completion unexpectedly offered an undiscovered image: %#v", got)
	}
}

func TestSingleByteReaderDoesNotReadAhead(t *testing.T) {
	input := strings.NewReader("image:tag\nprintf marker\nexit\n")
	reader := &singleByteReader{reader: input}
	buffer := make([]byte, 64)
	n, err := reader.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(buffer[:n]) != "i" {
		t.Fatalf("first read = %q (%d bytes)", buffer[:n], n)
	}
	remaining, err := io.ReadAll(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(remaining) != "mage:tag\nprintf marker\nexit\n" {
		t.Fatalf("underlying input after one-byte read = %q", remaining)
	}
}

func TestLaunchDockerSocketBreakoutPassesImagesToInteractiveCompletion(t *testing.T) {
	originalProbe := probeDockerSocket
	originalRun := runDockerSocketBreakout
	originalFind := findAvailableDockerSocketPaths
	originalCanComplete := canCompleteDockerImagePrompt
	originalCompletionLine := readDockerImageCompletionLine
	t.Cleanup(func() {
		probeDockerSocket = originalProbe
		runDockerSocketBreakout = originalRun
		findAvailableDockerSocketPaths = originalFind
		canCompleteDockerImagePrompt = originalCanComplete
		readDockerImageCompletionLine = originalCompletionLine
	})

	findAvailableDockerSocketPaths = func() []string { return nil }
	probeDockerSocket = func(_ context.Context, options dockersocket.Options) (dockersocket.Finding, error) {
		return dockersocket.Finding{
			SocketPath: options.SocketPath,
			AvailableImages: []string{
				"registry.example/team/tool:v2",
				"alpine:latest",
				"registry.example/team/tool:v2",
			},
		}, nil
	}
	canCompleteDockerImagePrompt = func(io.Reader, io.Writer, io.Writer) bool { return true }
	var gotCandidates []string
	readDockerImageCompletionLine = func(_ io.Reader, _, _ io.Writer, candidates []string) (string, error) {
		gotCandidates = append([]string(nil), candidates...)
		return "manually-entered:v1", nil
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

	stdin := &chunkReader{chunks: [][]byte{
		[]byte("/run/docker.sock\n"),
		[]byte("printf marker\nexit\n"),
	}}
	if err := launchDockerSocketBreakoutWithStreams(stdin, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}

	wantCandidates := []string{"alpine:latest", "registry.example/team/tool:v2"}
	if !reflect.DeepEqual(gotCandidates, wantCandidates) {
		t.Fatalf("completion candidates = %#v, want %#v", gotCandidates, wantCandidates)
	}
	if gotOptions.Image != "manually-entered:v1" {
		t.Fatalf("manually entered image = %q", gotOptions.Image)
	}
	if gotShellInput != "printf marker\nexit\n" {
		t.Fatalf("shell input = %q", gotShellInput)
	}
}

type chunkReader struct {
	chunks [][]byte
}

func (reader *chunkReader) Read(buffer []byte) (int, error) {
	if len(reader.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, reader.chunks[0])
	reader.chunks[0] = reader.chunks[0][n:]
	if len(reader.chunks[0]) == 0 {
		reader.chunks = reader.chunks[1:]
	}
	return n, nil
}

func TestAvailableDockerSocketPathsFiltersAndSortsDirectSockets(t *testing.T) {
	directory := t.TempDir()
	firstSocket := filepath.Join(directory, "first.sock")
	secondSocket := filepath.Join(directory, "second.sock")
	firstListener, err := net.Listen("unix", firstSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstListener.Close() })
	secondListener, err := net.Listen("unix", secondSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondListener.Close() })

	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "linked.sock")
	if err := os.Symlink(firstSocket, symlink); err != nil {
		t.Fatal(err)
	}

	got := availableDockerSocketPaths([]string{
		secondSocket,
		filepath.Join(directory, "missing.sock"),
		regular,
		symlink,
		firstSocket,
		secondSocket,
	})
	want := []string{firstSocket, secondSocket}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("availableDockerSocketPaths() = %#v, want %#v", got, want)
	}
}

func TestLaunchDockerSocketBreakoutListsNoSocketsBeforePrompt(t *testing.T) {
	originalProbe := probeDockerSocket
	originalFind := findAvailableDockerSocketPaths
	t.Cleanup(func() {
		probeDockerSocket = originalProbe
		findAvailableDockerSocketPaths = originalFind
	})
	findAvailableDockerSocketPaths = func() []string { return nil }
	probeDockerSocket = func(context.Context, dockersocket.Options) (dockersocket.Finding, error) {
		return dockersocket.Finding{}, nil
	}

	var stdout bytes.Buffer
	err := launchDockerSocketBreakoutWithStreams(strings.NewReader("/manual/docker.sock\n"), &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "image reference is required") {
		t.Fatalf("error = %v", err)
	}
	wantPrefix := "Available Docker socket paths: none found\n" +
		"Docker socket path [/var/run/docker.sock]: "
	if !strings.HasPrefix(stdout.String(), wantPrefix) {
		t.Fatalf("output = %q, want prefix %q", stdout.String(), wantPrefix)
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
