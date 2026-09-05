package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inguardians/peirates/internal/modules/containerescape"
	"github.com/inguardians/peirates/internal/modules/dockersocket"
	"github.com/inguardians/peirates/internal/modules/hostroot"
)

var scanContainerEscapes = func() error {
	return containerescape.Run(context.Background(), os.Stdout)
}

var probeDockerSocket = dockersocket.Probe
var runDockerSocketBreakout = dockersocket.Launch
var runHostRootBreakout = hostroot.Launch
var runHostRootBreakoutAt = hostroot.LaunchAt

var launchDockerSocketBreakout = func() error {
	return launchDockerSocketBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

var launchHostRootBreakout = func() error {
	return launchHostRootBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

func launchDockerSocketBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
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
	if len(finding.AvailableImages) > 0 {
		fmt.Fprintf(stdout, "Existing tagged images: %s\n", strings.Join(finding.AvailableImages, ", "))
	}

	image, err := readEscapePromptLine(reader, stdout,
		"Existing image reference (must contain /bin/sh and chroot): ")
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
