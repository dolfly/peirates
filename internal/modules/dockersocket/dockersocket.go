// Package dockersocket implements access to a Docker daemon host through an
// explicitly exposed Docker-compatible Unix socket.
package dockersocket

import (
	"context"
	"errors"
	"io"
	"time"
)

const (
	defaultRequestTimeout = 5 * time.Second
	defaultAttachTimeout  = 5 * time.Second
)

// ErrUnsupported is returned when Docker Unix-socket breakout support is not
// available on the current operating system.
var ErrUnsupported = errors.New("Docker socket breakout is supported only on Linux")

// Options describes one probe or breakout attempt. Launch requires Image to
// name an exact reference already present in the target daemon. Probe accepts
// an empty Image to return a minimal list of tagged local references. This
// package never pulls an image.
type Options struct {
	SocketPath string
	Image      string
	// Stdin should be a terminal, a finite reader, or a reader whose lifetime
	// the caller controls. Go cannot cancel an arbitrary blocked io.Reader.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// RequestTimeout bounds ordinary Docker API requests. AttachTimeout bounds
	// only the attach handshake; the attached shell itself has no time limit.
	RequestTimeout time.Duration
	AttachTimeout  time.Duration

	// RunID is optional and primarily useful for deterministic callers and
	// tests. When supplied, it must contain 24-64 lowercase hexadecimal
	// characters (the encoding of 12-32 bytes).
	RunID string
}

// Finding is the non-mutating evidence returned by Probe.
type Finding struct {
	SocketPath      string
	APIVersion      string
	ServerVersion   string
	OperatingSystem string
	Architecture    string
	Image           string
	ImageID         string
	AvailableImages []string
	Caveat          string
}

// Probe checks the socket and Docker API without creating, starting, or
// removing a container. If Options.Image is set, Probe inspects only that
// exact local reference. If it is empty, Probe returns the daemon's tagged
// local image references in AvailableImages so an operator can choose one.
func Probe(ctx context.Context, options Options) (Finding, error) {
	return probe(ctx, options)
}

// Launch verifies the selected image in a constrained disposable container,
// then creates and attaches to an owned privileged host-root shell. All
// containers created by Launch are removed before it returns when the daemon
// remains reachable and ownership can be verified.
func Launch(ctx context.Context, options Options) error {
	return launch(ctx, options)
}
