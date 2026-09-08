//go:build linux

package dockersocket

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRunID   = "0123456789abcdef01234567"
	probeID     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	breakoutID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type requestRecord struct {
	method string
	uri    string
	body   []byte
}

type fakeDockerDaemon struct {
	t                 *testing.T
	listener          net.Listener
	server            *http.Server
	socketPath        string
	mu                sync.Mutex
	requests          []requestRecord
	creates           []createContainerRequest
	createdNames      []string
	labels            map[string]map[string]string
	deleted           []string
	mainStarted       chan struct{}
	startMainOnce     sync.Once
	pingBody          string
	pingDelay         time.Duration
	versionBody       string
	imageListBody     string
	imageInspectCode  int
	probeCreateCode   int
	probeExit         int64
	shellExit         int64
	attachStatus      int
	attachDelay       time.Duration
	attachOutputDelay time.Duration
	attachOutput      string
	shellStartCode    int
	mismatchID        string
	mismatchInspectID string
	shellTTY          bool
}

func newFakeDockerDaemon(t *testing.T) *fakeDockerDaemon {
	t.Helper()
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	daemon := &fakeDockerDaemon{
		t: t, listener: listener, socketPath: socketPath,
		labels: make(map[string]map[string]string), mainStarted: make(chan struct{}),
		pingBody: "OK", versionBody: `{"ApiVersion":"1.43","MinAPIVersion":"1.25","Version":"25.0.0","Os":"linux","Arch":"amd64"}`,
		imageListBody:    `[{"RepoTags":["z/tool:2","a/tool:1"]},{"RepoTags":["a/tool:1","<none>:<none>",null]}]`,
		imageInspectCode: http.StatusOK, attachStatus: http.StatusSwitchingProtocols,
		probeCreateCode: http.StatusCreated,
		attachOutput:    "HOST_SHELL_READY\n", shellStartCode: http.StatusNoContent,
	}
	daemon.server = &http.Server{Handler: http.HandlerFunc(daemon.handle)}
	go func() { _ = daemon.server.Serve(listener) }()
	t.Cleanup(func() {
		_ = daemon.server.Close()
		_ = daemon.listener.Close()
	})
	return daemon
}

func (daemon *fakeDockerDaemon) handle(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	daemon.mu.Lock()
	daemon.requests = append(daemon.requests, requestRecord{method: request.Method, uri: request.RequestURI, body: body})
	daemon.mu.Unlock()

	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/_ping":
		if daemon.pingDelay != 0 {
			time.Sleep(daemon.pingDelay)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, daemon.pingBody)
	case request.Method == http.MethodGet && request.URL.Path == "/version":
		writeFakeResponse(writer, http.StatusOK, daemon.versionBody)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/images/json"):
		writeFakeResponse(writer, http.StatusOK, daemon.imageListBody)
	case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/images/") && strings.HasSuffix(request.URL.Path, "/json"):
		if daemon.imageInspectCode != http.StatusOK {
			writeFakeResponse(writer, daemon.imageInspectCode, "image is not present\nlocally")
			return
		}
		writeFakeResponse(writer, http.StatusOK, `{"Id":"`+testImageID+`"}`)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/containers/create"):
		var create createContainerRequest
		if err := json.Unmarshal(body, &create); err != nil {
			writeFakeResponse(writer, http.StatusBadRequest, err.Error())
			return
		}
		name := request.URL.Query().Get("name")
		id := breakoutID
		if strings.Contains(name, "image-probe") {
			id = probeID
		}
		daemon.mu.Lock()
		daemon.creates = append(daemon.creates, create)
		daemon.createdNames = append(daemon.createdNames, name)
		daemon.labels[id] = cloneLabels(create.Labels)
		daemon.labels[name] = cloneLabels(create.Labels)
		if id == breakoutID {
			daemon.shellTTY = create.TTY
		}
		daemon.mu.Unlock()
		if id == probeID && daemon.probeCreateCode != http.StatusCreated {
			writeFakeResponse(writer, daemon.probeCreateCode, "ambiguous create failure")
			return
		}
		writeFakeResponse(writer, http.StatusCreated, `{"Id":"`+id+`"}`)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/attach"):
		daemon.handleAttach(writer)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/start"):
		id := containerIDFromPath(request.URL.Path)
		if id == breakoutID && daemon.shellStartCode != http.StatusNoContent {
			writeFakeResponse(writer, daemon.shellStartCode, "injected start failure")
			return
		}
		if id == breakoutID {
			daemon.startMainOnce.Do(func() { close(daemon.mainStarted) })
		}
		writer.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/wait"):
		id := containerIDFromPath(request.URL.Path)
		status := daemon.shellExit
		if id == probeID {
			status = daemon.probeExit
		}
		writeFakeResponse(writer, http.StatusOK, fmt.Sprintf(`{"StatusCode":%d}`, status))
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/resize"):
		writer.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/containers/") && strings.HasSuffix(request.URL.Path, "/json"):
		reference := containerIDFromPath(request.URL.Path)
		id := reference
		if strings.Contains(reference, "image-probe") {
			id = probeID
		} else if strings.Contains(reference, "breakout") {
			id = breakoutID
		}
		daemon.mu.Lock()
		labels := cloneLabels(daemon.labels[reference])
		if len(labels) == 0 {
			labels = cloneLabels(daemon.labels[id])
		}
		daemon.mu.Unlock()
		if daemon.mismatchID == id {
			labels[ownershipLabel] = "not-owned-by-this-run"
		}
		responseID := id
		if daemon.mismatchInspectID == id {
			responseID = strings.Repeat("c", 64)
		}
		payload, _ := json.Marshal(map[string]any{"Id": responseID, "Config": map[string]any{"Labels": labels}})
		writeFakeResponse(writer, http.StatusOK, string(payload))
	case request.Method == http.MethodDelete && strings.Contains(request.URL.Path, "/containers/"):
		id := containerIDFromPath(request.URL.Path)
		daemon.mu.Lock()
		daemon.deleted = append(daemon.deleted, id)
		daemon.mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeFakeResponse(writer, http.StatusNotFound, "unexpected fake Docker route")
	}
}

func (daemon *fakeDockerDaemon) handleAttach(writer http.ResponseWriter) {
	if daemon.attachDelay != 0 {
		time.Sleep(daemon.attachDelay)
	}
	if daemon.attachStatus != http.StatusSwitchingProtocols {
		writeFakeResponse(writer, daemon.attachStatus, "attach rejected")
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writeFakeResponse(writer, http.StatusInternalServerError, "hijacking unavailable")
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_, _ = buffered.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = buffered.Flush()
	go func() {
		defer connection.Close()
		inputDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, connection)
			close(inputDone)
		}()
		select {
		case <-daemon.mainStarted:
			if daemon.attachOutputDelay != 0 {
				time.Sleep(daemon.attachOutputDelay)
			}
			daemon.mu.Lock()
			tty := daemon.shellTTY
			daemon.mu.Unlock()
			if tty {
				_, _ = io.WriteString(connection, daemon.attachOutput)
			} else {
				var header [8]byte
				header[0] = 1
				binary.BigEndian.PutUint32(header[4:], uint32(len(daemon.attachOutput)))
				_, _ = connection.Write(header[:])
				_, _ = io.WriteString(connection, daemon.attachOutput)
			}
			select {
			case <-inputDone:
			case <-time.After(2 * time.Second):
			}
		case <-time.After(2 * time.Second):
		}
	}()
}

func writeFakeResponse(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

func cloneLabels(labels map[string]string) map[string]string {
	copy := make(map[string]string, len(labels))
	for key, value := range labels {
		copy[key] = value
	}
	return copy
}

func containerIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if part == "containers" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return ""
}

func (daemon *fakeDockerDaemon) snapshot() ([]requestRecord, []createContainerRequest, []string) {
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	requests := append([]requestRecord(nil), daemon.requests...)
	creates := append([]createContainerRequest(nil), daemon.creates...)
	deleted := append([]string(nil), daemon.deleted...)
	return requests, creates, deleted
}

type fakeTerminal struct {
	mu           sync.Mutex
	makeRawCalls int
	restoreCalls int
	sizeCalls    int
	makeRawErr   error
	restoreErr   error
	height       uint
	width        uint
	sized        chan struct{}
	sizeOnce     sync.Once
	nonTerminal  bool
}

func (terminal *fakeTerminal) isTerminal(io.Reader) bool { return !terminal.nonTerminal }

func (terminal *fakeTerminal) makeRaw(io.Reader) (func() error, error) {
	terminal.mu.Lock()
	terminal.makeRawCalls++
	terminal.mu.Unlock()
	if terminal.makeRawErr != nil {
		return nil, terminal.makeRawErr
	}
	return func() error {
		terminal.mu.Lock()
		defer terminal.mu.Unlock()
		terminal.restoreCalls++
		return terminal.restoreErr
	}, nil
}

func (terminal *fakeTerminal) size(io.Reader) (height, width uint, ok bool) {
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	terminal.sizeCalls++
	if terminal.sized != nil {
		terminal.sizeOnce.Do(func() { close(terminal.sized) })
	}
	if terminal.height == 0 || terminal.width == 0 {
		return 0, 0, false
	}
	return terminal.height, terminal.width, true
}

func (terminal *fakeTerminal) counts() (int, int, int) {
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	return terminal.makeRawCalls, terminal.restoreCalls, terminal.sizeCalls
}

func TestProbeInspectsOnlyExplicitLocalImage(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	finding, err := Probe(context.Background(), Options{
		SocketPath: daemon.socketPath, Image: "example/tool:latest", RunID: testRunID,
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if finding.SocketPath != daemon.socketPath || finding.APIVersion != "1.43" || finding.ServerVersion != "25.0.0" ||
		finding.OperatingSystem != "linux" || finding.Architecture != "amd64" || finding.Image != "example/tool:latest" ||
		finding.ImageID != testImageID || len(finding.AvailableImages) != 0 {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if !strings.Contains(finding.Caveat, "nested or remote") {
		t.Fatalf("missing daemon-host caveat: %q", finding.Caveat)
	}
	requests, _, _ := daemon.snapshot()
	assertRequestSequence(t, requests, []string{
		"GET /_ping", "GET /version", "GET /v1.43/images/example%2Ftool:latest/json",
	})
	assertNoImagePull(t, requests)
}

func TestProbeListsOnlyTaggedLocalReferencesForSelection(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	finding, err := Probe(context.Background(), Options{
		SocketPath: daemon.socketPath, RunID: testRunID, RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/tool:1", "z/tool:2"}
	if !reflect.DeepEqual(finding.AvailableImages, want) || finding.Image != "" || finding.ImageID != "" {
		t.Fatalf("finding = %#v, want available images %#v", finding, want)
	}
	requests, _, _ := daemon.snapshot()
	assertRequestSequence(t, requests, []string{"GET /_ping", "GET /version", "GET /v1.43/images/json?all=0"})
	assertNoImagePull(t, requests)
}

func TestProbeRejectsInvalidSocketTargets(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon := newFakeDockerDaemon(t)
	symlink := filepath.Join(directory, "socket-link")
	if err := os.Symlink(daemon.socketPath, symlink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path, want string
	}{
		{name: "relative", path: "docker.sock", want: "must be absolute"},
		{name: "unclean", path: directory + "/../" + filepath.Base(directory) + "/regular", want: "clean and unambiguous"},
		{name: "regular", path: regular, want: "not a Unix socket"},
		{name: "symlink", path: symlink, want: "must not be a symbolic link"},
		{name: "missing", path: filepath.Join(directory, "missing"), want: "inspect Docker socket"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Probe(context.Background(), Options{SocketPath: test.path, RunID: testRunID})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestProbeAllowsResolvedParentSymlinkWithoutFollowingSocketSymlink(t *testing.T) {
	realParent := t.TempDir()
	linkedRoot := t.TempDir()
	linkedParent := filepath.Join(linkedRoot, "run")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(realParent, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/_ping":
			_, _ = io.WriteString(writer, "OK")
		case "/version":
			_, _ = io.WriteString(writer, `{"ApiVersion":"1.43","Version":"test","Os":"linux","Arch":"amd64"}`)
		default:
			_, _ = io.WriteString(writer, `[]`)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	linkedSocket := filepath.Join(linkedParent, "docker.sock")
	finding, err := Probe(context.Background(), Options{SocketPath: linkedSocket, RunID: testRunID, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if finding.SocketPath != linkedSocket {
		t.Fatalf("socket path = %q, want %q", finding.SocketPath, linkedSocket)
	}
}

func TestSocketGuardRejectsReplacedSocketIdentity(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "docker.sock")
	first, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := openSocketGuard(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.close()
	defer first.Close()
	if err := os.Remove(socketPath); err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	connection, err := guard.dialContext(context.Background(), "unix", "docker")
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("error = %v", err)
	}
}

func TestProbeBoundsTimeoutAndBodies(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		daemon := newFakeDockerDaemon(t)
		daemon.pingDelay = 100 * time.Millisecond
		_, err := Probe(context.Background(), Options{
			SocketPath: daemon.socketPath, RunID: testRunID, RequestTimeout: 10 * time.Millisecond,
		})
		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("oversized ping", func(t *testing.T) {
		daemon := newFakeDockerDaemon(t)
		daemon.pingBody = strings.Repeat("x", maximumPingBody+1)
		_, err := Probe(context.Background(), Options{
			SocketPath: daemon.socketPath, RunID: testRunID, RequestTimeout: time.Second,
		})
		if err == nil || !strings.Contains(err.Error(), "exceeds 64 bytes") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestProbeReportsImageAbsenceWithoutPull(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.imageInspectCode = http.StatusNotFound
	_, err := Probe(context.Background(), Options{
		SocketPath: daemon.socketPath, Image: "missing:latest", RunID: testRunID, RequestTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "no pull was attempted") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("error = %q", err)
	}
	requests, _, _ := daemon.snapshot()
	assertNoImagePull(t, requests)
}

func TestLaunchCreatesAttachedOwnedShellAndCleansExactIDs(t *testing.T) {
	t.Setenv("TERM", "xterm-test")
	daemon := newFakeDockerDaemon(t)
	terminal := &fakeTerminal{height: 24, width: 80}
	var stdout, stderr bytes.Buffer
	err := launchForTest(context.Background(), daemon.socketPath, &stdout, &stderr, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Entering the Docker daemon host filesystem") ||
		!strings.Contains(stdout.String(), daemon.attachOutput) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "may be nested or remote") ||
		!strings.Contains(stderr.String(), "Creating a privileged container from fixture:latest...") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	makeRawCalls, restoreCalls, sizeCalls := terminal.counts()
	if makeRawCalls != 1 || restoreCalls != 1 || sizeCalls == 0 {
		t.Fatalf("terminal calls = raw:%d restore:%d size:%d", makeRawCalls, restoreCalls, sizeCalls)
	}

	requests, creates, deleted := daemon.snapshot()
	if len(creates) != 2 {
		t.Fatalf("create requests = %d, want 2", len(creates))
	}
	probe := creates[0]
	if probe.Image != "fixture:latest" || probe.User != "0:0" || !probe.NetworkDisabled || !probe.HostConfig.ReadonlyRootfs ||
		!reflect.DeepEqual(probe.HostConfig.CapDrop, []string{"ALL"}) ||
		!reflect.DeepEqual(probe.HostConfig.SecurityOptions, []string{"no-new-privileges"}) ||
		probe.HostConfig.Privileged {
		t.Fatalf("unsafe image probe request: %#v", probe)
	}
	shell := creates[1]
	if shell.Image != "fixture:latest" || shell.User != "0:0" ||
		!reflect.DeepEqual(shell.Environment, []string{"TERM=xterm-test"}) || !shell.TTY || !shell.OpenStdin || !shell.StdinOnce ||
		!shell.AttachStdin || !shell.AttachStdout || !shell.AttachStderr ||
		!reflect.DeepEqual(shell.Entrypoint, []string{"/bin/sh", "-c"}) ||
		!reflect.DeepEqual(shell.Command, []string{"exec chroot /host /bin/sh -i"}) ||
		!shell.HostConfig.Privileged || shell.HostConfig.PIDMode != "host" ||
		!reflect.DeepEqual(shell.HostConfig.Binds, []string{"/:/host:rw"}) {
		t.Fatalf("unexpected breakout request: %#v", shell)
	}
	if shell.Labels[ownershipLabel] != testRunID+"-"+breakoutContainerTag ||
		probe.Labels[ownershipLabel] != testRunID+"-"+probeContainerTag {
		t.Fatalf("ownership labels missing: probe=%#v shell=%#v", probe.Labels, shell.Labels)
	}
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
	if !containsRequest(requests, "POST", "/containers/"+breakoutID+"/attach?") ||
		!containsRequest(requests, "POST", "/containers/"+breakoutID+"/resize?") {
		t.Fatalf("attach/resize requests missing: %#v", requests)
	}
	assertNoImagePull(t, requests)
	assertCleanupAfterInspect(t, requests, probeID)
	assertCleanupAfterInspect(t, requests, breakoutID)
}

func TestDockerShellEnvironmentUsesDumbTerminalForNonTerminalInput(t *testing.T) {
	if got := dockerShellEnvironment(false); !reflect.DeepEqual(got, []string{"TERM=dumb"}) {
		t.Fatalf("dockerShellEnvironment() = %#v", got)
	}
	t.Setenv("TERM", "screen-test")
	if got := dockerShellEnvironment(true); !reflect.DeepEqual(got, []string{"TERM=screen-test"}) {
		t.Fatalf("dockerShellEnvironment(terminal) = %#v", got)
	}
}

func TestLaunchUsesMultiplexedNonTTYStreamForScriptedInput(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	terminal := &fakeTerminal{nonTerminal: true}
	var stdout bytes.Buffer
	if err := launchForTest(context.Background(), daemon.socketPath, &stdout, io.Discard, terminal); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), daemon.attachOutput) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	_, creates, deleted := daemon.snapshot()
	if len(creates) != 2 {
		t.Fatalf("create requests = %d, want 2", len(creates))
	}
	shell := creates[1]
	if shell.TTY || !reflect.DeepEqual(shell.Command, []string{"exec chroot /host /bin/sh"}) ||
		!reflect.DeepEqual(shell.Environment, []string{"TERM=dumb"}) {
		t.Fatalf("unexpected scripted breakout request: %#v", shell)
	}
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
	makeRawCalls, _, sizeCalls := terminal.counts()
	if makeRawCalls != 0 || sizeCalls != 0 {
		t.Fatalf("non-terminal stream used terminal controls: raw=%d size=%d", makeRawCalls, sizeCalls)
	}
}

func TestCopyDockerOutputRejectsInvalidFrames(t *testing.T) {
	for _, input := range [][]byte{
		{3, 0, 0, 0, 0, 0, 0, 0},
		{1, 1, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 2, 'x'},
	} {
		if err := copyDockerOutput(bytes.NewReader(input), io.Discard, io.Discard, false); err == nil {
			t.Fatalf("copyDockerOutput(%v) unexpectedly succeeded", input)
		}
	}
}

func TestCopyDockerOutputRoutesMultiplexedStreams(t *testing.T) {
	var framed bytes.Buffer
	for _, frame := range []struct {
		channel byte
		body    string
	}{{channel: 1, body: "stdout"}, {channel: 2, body: "stderr"}} {
		var header [8]byte
		header[0] = frame.channel
		binary.BigEndian.PutUint32(header[4:], uint32(len(frame.body)))
		framed.Write(header[:])
		framed.WriteString(frame.body)
	}
	var stdout, stderr bytes.Buffer
	if err := copyDockerOutput(&framed, &stdout, &stderr, false); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestLaunchRejectsImageWithoutToolsAndRemovesProbe(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.probeExit = 127
	terminal := &fakeTerminal{}
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, terminal)
	if err == nil || !strings.Contains(err.Error(), "does not provide usable /bin/sh and chroot") {
		t.Fatalf("error = %v", err)
	}
	requests, creates, deleted := daemon.snapshot()
	if len(creates) != 1 || !reflect.DeepEqual(deleted, []string{probeID}) {
		t.Fatalf("creates=%d deleted=%#v", len(creates), deleted)
	}
	if containsRequest(requests, "POST", "/attach?") {
		t.Fatal("breakout attach occurred after failed image probe")
	}
	makeRawCalls, restoreCalls, _ := terminal.counts()
	if makeRawCalls != 0 || restoreCalls != 0 {
		t.Fatalf("terminal changed after image rejection: raw=%d restore=%d", makeRawCalls, restoreCalls)
	}
}

func TestLaunchRecoversAndRemovesAmbiguouslyCreatedOwnedContainer(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.probeCreateCode = http.StatusInternalServerError
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, &fakeTerminal{})
	if err == nil || !strings.Contains(err.Error(), "ambiguous create failure") {
		t.Fatalf("error = %v", err)
	}
	requests, creates, deleted := daemon.snapshot()
	if len(creates) != 1 || !reflect.DeepEqual(deleted, []string{probeID}) {
		t.Fatalf("creates=%d deleted=%#v", len(creates), deleted)
	}
	if !containsRequest(requests, http.MethodGet, "/containers/peirates-image-probe-"+testRunID+"/json") {
		t.Fatalf("ambiguous creation was not resolved by exact name: %#v", requests)
	}
	assertCleanupAfterInspect(t, requests, probeID)
}

func TestLaunchRestoresTerminalAndCleansAfterStartFailure(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.shellStartCode = http.StatusInternalServerError
	terminal := &fakeTerminal{}
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, terminal)
	if err == nil || !strings.Contains(err.Error(), "injected start failure") {
		t.Fatalf("error = %v", err)
	}
	_, _, deleted := daemon.snapshot()
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
	makeRawCalls, restoreCalls, _ := terminal.counts()
	if makeRawCalls != 1 || restoreCalls != 1 {
		t.Fatalf("terminal calls = raw:%d restore:%d", makeRawCalls, restoreCalls)
	}
}

func TestLaunchReportsTerminalRestoreFailureAndCleans(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	terminal := &fakeTerminal{restoreErr: fmt.Errorf("injected restore failure")}
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, terminal)
	if err == nil || !strings.Contains(err.Error(), "restore terminal: injected restore failure") {
		t.Fatalf("error = %v", err)
	}
	_, _, deleted := daemon.snapshot()
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
	makeRawCalls, restoreCalls, _ := terminal.counts()
	if makeRawCalls != 1 || restoreCalls != 1 {
		t.Fatalf("terminal calls = raw:%d restore:%d", makeRawCalls, restoreCalls)
	}
}

func TestLaunchRefusesCleanupWhenOwnershipLabelChanges(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.mismatchID = probeID
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, &fakeTerminal{})
	if err == nil || !strings.Contains(err.Error(), "ownership label does not match") {
		t.Fatalf("error = %v", err)
	}
	_, creates, deleted := daemon.snapshot()
	if len(creates) != 1 || len(deleted) != 0 {
		t.Fatalf("creates=%d deleted=%#v", len(creates), deleted)
	}
}

func TestLaunchRefusesCleanupWhenInspectReturnsDifferentID(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.mismatchInspectID = probeID
	err := launchForTest(context.Background(), daemon.socketPath, io.Discard, io.Discard, &fakeTerminal{})
	if err == nil || !strings.Contains(err.Error(), "inspection returned a different container ID") {
		t.Fatalf("error = %v", err)
	}
	_, creates, deleted := daemon.snapshot()
	if len(creates) != 1 || len(deleted) != 0 {
		t.Fatalf("creates=%d deleted=%#v", len(creates), deleted)
	}
}

func TestLaunchBoundsAttachHandshakeAndStillCleans(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.attachDelay = 100 * time.Millisecond
	options := Options{
		SocketPath: daemon.socketPath, Image: "fixture:latest", RunID: testRunID,
		Stdin: strings.NewReader("exit\n"), Stdout: io.Discard, Stderr: io.Discard,
		RequestTimeout: time.Second, AttachTimeout: 10 * time.Millisecond,
	}
	normalized, err := normalizeOptions(options, true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newDockerClient(normalized)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	err = launchWithClient(context.Background(), normalized, client, &fakeTerminal{})
	if err == nil || !strings.Contains(err.Error(), "attach") {
		t.Fatalf("error = %v", err)
	}
	_, _, deleted := daemon.snapshot()
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
}

func TestLaunchCancellationRestoresTerminalAndCleans(t *testing.T) {
	daemon := newFakeDockerDaemon(t)
	daemon.attachOutputDelay = 200 * time.Millisecond
	terminal := &fakeTerminal{sized: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- launchForTest(ctx, daemon.socketPath, io.Discard, io.Discard, terminal)
	}()
	select {
	case <-terminal.sized:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("privileged shell container did not start")
	}
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("error = %v", err)
	}
	_, _, deleted := daemon.snapshot()
	if !reflect.DeepEqual(deleted, []string{probeID, breakoutID}) {
		t.Fatalf("deleted IDs = %#v", deleted)
	}
	makeRawCalls, restoreCalls, _ := terminal.counts()
	if makeRawCalls != 1 || restoreCalls != 1 {
		t.Fatalf("terminal calls = raw:%d restore:%d", makeRawCalls, restoreCalls)
	}
}

func TestNormalizeOptionsRequiresExactLaunchImageAndValidRunID(t *testing.T) {
	base := Options{SocketPath: "/run/docker.sock", Image: "fixture:latest", RunID: testRunID}
	tests := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{name: "missing image", mutate: func(options *Options) { options.Image = "" }, want: "already-present Docker image"},
		{name: "newline image", mutate: func(options *Options) { options.Image = "bad\nname" }, want: "invalid characters"},
		{name: "run ID", mutate: func(options *Options) { options.RunID = "predictable" }, want: "lowercase hexadecimal"},
		{name: "negative timeout", mutate: func(options *Options) { options.RequestTimeout = -1 }, want: "cannot be negative"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.mutate(&options)
			_, err := normalizeOptions(options, true)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateAPIVersion(t *testing.T) {
	tests := []struct {
		maximum, minimum, want string
	}{
		{maximum: "1.43", minimum: "1.25"},
		{maximum: "1.24", minimum: "1.12", want: "older than required"},
		{maximum: "not-a-version", want: "invalid Docker API version"},
		{maximum: "1.43", minimum: "bad", want: "invalid minimum"},
	}
	for _, test := range tests {
		err := validateAPIVersion(test.maximum, test.minimum)
		if test.want == "" && err != nil {
			t.Fatalf("validateAPIVersion(%q, %q): %v", test.maximum, test.minimum, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Fatalf("error = %v, want %q", err, test.want)
		}
	}
}

func TestSafeErrorTextRemovesControlCharacters(t *testing.T) {
	if got := safeErrorText([]byte("bad\nsecret\r\x00value")); got != "bad secret  value" {
		t.Fatalf("safeErrorText() = %q", got)
	}
}

func launchForTest(ctx context.Context, socket string, stdout, stderr io.Writer, terminal terminalController) error {
	options := Options{
		SocketPath: socket, Image: "fixture:latest", RunID: testRunID,
		Stdin: strings.NewReader("exit\n"), Stdout: stdout, Stderr: stderr,
		RequestTimeout: time.Second, AttachTimeout: time.Second,
	}
	normalized, err := normalizeOptions(options, true)
	if err != nil {
		return err
	}
	client, err := newDockerClient(normalized)
	if err != nil {
		return err
	}
	defer client.close()
	return launchWithClient(ctx, normalized, client, terminal)
}

func assertRequestSequence(t *testing.T, requests []requestRecord, want []string) {
	t.Helper()
	got := make([]string, 0, len(requests))
	for _, request := range requests {
		got = append(got, request.method+" "+request.uri)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requests = %#v, want %#v", got, want)
	}
}

func assertNoImagePull(t *testing.T, requests []requestRecord) {
	t.Helper()
	for _, request := range requests {
		if strings.Contains(request.uri, "/images/create") {
			t.Fatalf("unexpected image pull: %s %s", request.method, request.uri)
		}
	}
}

func containsRequest(requests []requestRecord, method, uriPart string) bool {
	for _, request := range requests {
		if request.method == method && strings.Contains(request.uri, uriPart) {
			return true
		}
	}
	return false
}

func assertCleanupAfterInspect(t *testing.T, requests []requestRecord, id string) {
	t.Helper()
	inspectIndex, deleteIndex := -1, -1
	for index, request := range requests {
		if request.method == http.MethodGet && strings.Contains(request.uri, "/containers/"+id+"/json") {
			inspectIndex = index
		}
		if request.method == http.MethodDelete && strings.Contains(request.uri, "/containers/"+id+"?force=1&v=1") {
			deleteIndex = index
		}
	}
	if inspectIndex < 0 || deleteIndex <= inspectIndex {
		t.Fatalf("container %s cleanup order invalid: inspect=%d delete=%d", id, inspectIndex, deleteIndex)
	}
}
