package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ergochat/readline"
	"github.com/inguardians/peirates/internal/modules/containerescape"
	"github.com/inguardians/peirates/internal/modules/dockersocket"
	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"github.com/inguardians/peirates/internal/modules/hostroot"
	"golang.org/x/term"
)

const dockerImagePrompt = "Existing image reference (must contain /bin/sh and chroot): "

var scanContainerEscapes = func() error {
	return containerescape.Run(context.Background(), os.Stdout)
}

var probeDockerSocket = dockersocket.Probe
var runDockerSocketBreakout = dockersocket.Launch
var runHostRootBreakout = hostroot.Launch
var runHostRootBreakoutAt = hostroot.LaunchAt
var findAvailableDockerSocketPaths = func() []string {
	candidates := escapeutil.DockerSocketPaths(os.Getenv("DOCKER_HOST"), nil)
	return availableDockerSocketPaths(candidates)
}
var canCompleteDockerImagePrompt = supportsDockerImagePromptCompletion
var readDockerImageCompletionLine = readDockerImageLineWithCompletion

var launchDockerSocketBreakout = func() error {
	return launchDockerSocketBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

var launchHostRootBreakout = func() error {
	return launchHostRootBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

func launchDockerSocketBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
	if err := writeAvailableDockerSocketPaths(stdout, findAvailableDockerSocketPaths()); err != nil {
		return fmt.Errorf("list available Docker socket paths: %w", err)
	}
	socketPath, err := readEscapePromptLine(reader, stdout,
		"Docker socket path [/var/run/docker.sock]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Docker socket path: %w", err)
	}
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	finding, err := probeDockerSocket(context.Background(), dockersocket.Options{SocketPath: socketPath})
	if err != nil {
		return fmt.Errorf("probe Docker socket: %w", err)
	}
	if finding.ServerVersion != "" {
		fmt.Fprintf(stdout, "Docker daemon %s (%s/%s) is reachable through %s.\n",
			finding.ServerVersion, finding.OperatingSystem, finding.Architecture, socketPath)
	}
	if finding.Caveat != "" {
		fmt.Fprintln(stdout, finding.Caveat)
	}
	availableImages := dockerImageCompletionCandidates(finding.AvailableImages)
	if len(availableImages) > 0 {
		fmt.Fprintf(stdout, "Existing tagged images: %s\n", strings.Join(availableImages, ", "))
	}

	image, err := readDockerImageReference(reader, stdin, stdout, stderr, availableImages)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Docker image: %w", err)
	}
	if image == "" {
		return errors.New("an existing Docker image reference is required")
	}

	return runDockerSocketBreakout(context.Background(), dockersocket.Options{
		SocketPath: socketPath,
		Image:      image,
		Stdin:      remainingEscapeInput(reader, stdin),
		Stdout:     stdout,
		Stderr:     stderr,
	})
}

func dockerImageCompletionCandidates(images []string) []string {
	return escapeutil.SortedUnique(images)
}

func setUpDockerImageCompletion(images []string) *readline.PrefixCompleter {
	items := make([]*readline.PrefixCompleter, 0, len(images))
	for _, image := range dockerImageCompletionCandidates(images) {
		items = append(items, readline.PcItem(image))
	}
	return readline.NewPrefixCompleter(items...)
}

func readDockerImageReference(reader *bufio.Reader, original io.Reader, stdout, stderr io.Writer, images []string) (string, error) {
	// Keep using the shared buffered reader when input is piped or the socket
	// prompt has already read ahead. This preserves all subsequent shell input.
	if reader.Buffered() > 0 || !canCompleteDockerImagePrompt(original, stdout, stderr) {
		return readEscapePromptLine(reader, stdout, dockerImagePrompt)
	}
	return readDockerImageCompletionLine(original, stdout, stderr, images)
}

func supportsDockerImagePromptCompletion(stdin io.Reader, stdout, stderr io.Writer) bool {
	input, ok := stdin.(*os.File)
	if !ok || input.Fd() != os.Stdin.Fd() || !term.IsTerminal(int(input.Fd())) {
		return false
	}
	return writerIsTerminal(stdout) || writerIsTerminal(stderr)
}

func writerIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func readDockerImageLineWithCompletion(stdin io.Reader, stdout, stderr io.Writer, images []string) (string, error) {
	lineReader, err := readline.NewEx(&readline.Config{
		Prompt:                 dockerImagePrompt,
		HistoryLimit:           -1,
		DisableAutoSaveHistory: true,
		AutoComplete:           setUpDockerImageCompletion(images),
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		Stdin:                  &singleByteReader{reader: stdin},
		Stdout:                 stdout,
		Stderr:                 stderr,
	})
	if err != nil {
		return "", err
	}
	defer lineReader.Close()

	line, err := lineReader.Readline()
	return strings.TrimSpace(line), err
}

// singleByteReader prevents readline's private bufio.Reader from retaining
// bytes intended for the breakout shell after the image prompt completes.
type singleByteReader struct {
	reader io.Reader
}

func (reader *singleByteReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	return reader.reader.Read(buffer[:1])
}

func availableDockerSocketPaths(candidates []string) []string {
	var available []string
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		available = append(available, path)
	}
	return escapeutil.SortedUnique(available)
}

func writeAvailableDockerSocketPaths(stdout io.Writer, paths []string) error {
	if len(paths) == 0 {
		_, err := fmt.Fprintln(stdout, "Available Docker socket paths: none found")
		return err
	}
	if _, err := fmt.Fprintln(stdout, "Available Docker socket paths:"); err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := fmt.Fprintf(stdout, "- %s\n", path); err != nil {
			return err
		}
	}
	return nil
}

func launchHostRootBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
	target, err := readEscapePromptLine(reader, stdout,
		"Mounted host-root path [auto-detect]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read host-root path: %w", err)
	}
	if target == "" {
		return runHostRootBreakout(remainingEscapeInput(reader, stdin), stdout, stderr)
	}
	return runHostRootBreakoutAt(target, remainingEscapeInput(reader, stdin), stdout, stderr)
}

func readEscapePromptLine(reader *bufio.Reader, stdout io.Writer, prompt string) (string, error) {
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func remainingEscapeInput(reader *bufio.Reader, original io.Reader) io.Reader {
	if reader.Buffered() == 0 {
		return original
	}
	return reader
}
