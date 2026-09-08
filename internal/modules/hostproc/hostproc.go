// Package hostproc implements a temporary core_pattern-based host breakout
// through a positively qualified host procfs mount.
package hostproc

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

const (
	// CrashWorkerArgument selects the disposable process that intentionally
	// crashes to invoke the temporary host core handler.
	CrashWorkerArgument = "--internal-hostproc-core-crash-worker"

	// ConfirmationToken is required before replacing a non-piped core_pattern.
	ConfirmationToken = "OVERWRITE-HOST-CORE-PATTERN"

	// PipedHandlerOverrideToken is required before replacing an existing piped
	// crash handler.
	PipedHandlerOverrideToken = "REPLACE-PIPED-CORE-HANDLER"

	defaultTriggerTimeout = 10 * time.Second
	outputPrefix          = "[hostproc-core-pattern-breakout]"
)

// ErrUnsupported is returned on platforms without Linux procfs and core dump
// handler support.
var ErrUnsupported = errors.New("host-proc core_pattern breakout is supported only on Linux")

// Options configures a breakout attempt. ConfirmMutation must be true. When
// ExpectedCorePattern is non-nil, Launch refuses to proceed if the value has
// changed since the operator reviewed it.
type Options struct {
	HostProcPath             string
	ExpectedCorePattern      *string
	AllowReplacePipedHandler bool
	ConfirmMutation          bool
	TriggerTimeout           time.Duration
	Stdin                    io.Reader
	Stdout                   io.Writer
	Stderr                   io.Writer
}

// Finding is the read-only preflight result used for operator review.
type Finding struct {
	HostProcPath        string
	CorePatternPath     string
	OriginalCorePattern string
	CorePatternIdentity escapeutil.FileIdentity
	Caveat              string
}

type normalizedOptions struct {
	Options
}

// Probe performs the read-only preflight without creating payloads, changing
// core_pattern, or crashing a process.
func Probe(ctx context.Context, options Options) (Finding, error) {
	return probe(ctx, normalizeOptions(options))
}

// Launch repeats the complete preflight immediately before the temporary
// mutation and host-shell relay.
func Launch(ctx context.Context, options Options) error {
	return launch(ctx, normalizeOptions(options))
}

// RunCrashWorker intentionally terminates only the disposable internal worker
// with a core-producing signal.
func RunCrashWorker(args []string, stderr *os.File) int {
	return runCrashWorker(args, stderr)
}

func normalizeOptions(options Options) normalizedOptions {
	if options.TriggerTimeout <= 0 {
		options.TriggerTimeout = defaultTriggerTimeout
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	return normalizedOptions{Options: options}
}
