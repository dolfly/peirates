// Package hostpidptrace runs one bounded command from a disposable child of an
// explicitly selected process at visible PID 1's namespace boundary.
package hostpidptrace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	// WorkerArgument selects the private ptrace worker. The command and target
	// metadata are transferred through anonymous pipes, never argv or env.
	WorkerArgument = "--internal-hostpid-ptrace-worker"

	DefaultTimeout     = 30 * time.Second
	DefaultOutputLimit = int64(1024 * 1024)
	MaxCommandBytes    = 4096
	maxProtocolBytes   = 24*1024*1024 + MaxCommandBytes
)

var ErrUnsupported = errors.New("hostPID ptrace breakout is supported only on Linux AMD64")

// Identity is a stable device/inode identity for a namespace or root handle.
type Identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Candidate contains the evidence used to qualify a disposable trace target.
// CommandLine is sanitized and bounded for display; it is never used to find
// or reopen the process.
type Candidate struct {
	PID               int                 `json:"pid"`
	StartTime         uint64              `json:"start_time"`
	Comm              string              `json:"comm"`
	Executable        string              `json:"executable"`
	CommandLine       string              `json:"command_line"`
	CommandLineDigest string              `json:"command_line_digest"`
	State             byte                `json:"state"`
	UIDs              [4]uint32           `json:"uids"`
	Threads           int                 `json:"threads"`
	TracerPID         int                 `json:"tracer_pid"`
	CoreDumping       int                 `json:"core_dumping"`
	NamespaceIDs      map[string]Identity `json:"namespace_ids"`
	RootID            Identity            `json:"root_id"`
	PIDDepth          int                 `json:"pid_depth"`
}

// ProbeResult describes the read-only eligibility check and candidate list.
type ProbeResult struct {
	Candidates    []Candidate
	YamaScope     *int
	SeccompMode   int
	SecurityLabel string
	Warnings      []string
}

// RunOptions configures one worker invocation.
type RunOptions struct {
	Target      Candidate
	Command     string
	Timeout     time.Duration
	OutputLimit int64
}

// Result separates the command result from cleanup/restoration evidence.
type Result struct {
	Output           []byte `json:"output"`
	OutputTruncated  bool   `json:"output_truncated"`
	CommandCompleted bool   `json:"command_completed"`
	ExitCode         int    `json:"exit_code"`
	Signal           int    `json:"signal"`
	TargetRestored   bool   `json:"target_restored"`
	TargetDetached   bool   `json:"target_detached"`
	OutputRemoved    bool   `json:"output_removed"`
	Stage            string `json:"stage"`
}

// ConfirmationPhrase is deliberately PID-specific and exact.
func ConfirmationPhrase(pid int) string {
	return fmt.Sprintf("TRACE-DISPOSABLE-HOST-PROCESS-%d", pid)
}

func normalizeRunOptions(options RunOptions) (RunOptions, error) {
	if options.Target.PID <= 1 {
		return options, errors.New("a disposable target PID greater than 1 is required")
	}
	if len(options.Command) == 0 {
		return options, errors.New("a non-empty host command is required")
	}
	if len(options.Command) > MaxCommandBytes {
		return options, fmt.Errorf("host command exceeds %d bytes", MaxCommandBytes)
	}
	for _, value := range []byte(options.Command) {
		if value == 0 {
			return options, errors.New("host command contains a NUL byte")
		}
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout > 5*time.Minute {
		return options, errors.New("host command timeout exceeds 5 minutes")
	}
	if options.OutputLimit <= 0 {
		options.OutputLimit = DefaultOutputLimit
	}
	if options.OutputLimit > 16*1024*1024 {
		return options, errors.New("host command output limit exceeds 16 MiB")
	}
	return options, nil
}

// Probe performs read-only preflight and candidate enumeration.
func Probe(ctx context.Context) (ProbeResult, error) { return probePlatform(ctx) }

// Launch sends a bounded request to a private re-exec worker.
func Launch(ctx context.Context, options RunOptions) (Result, error) {
	options, err := normalizeRunOptions(options)
	if err != nil {
		return Result{}, err
	}
	return launchWorker(ctx, options)
}

// RunWorker handles the private worker mode using inherited request and result
// pipes. It returns the process exit status; diagnostics contain no command.
func RunWorker(args []string, request, response io.ReadWriter, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "[hostpid-ptrace-breakout] internal worker does not accept arguments")
		return 2
	}
	if err := runWorker(request, response); err != nil {
		fmt.Fprintf(stderr, "[hostpid-ptrace-breakout] private worker failed: %v\n", err)
		return 1
	}
	return 0
}

// RunInheritedWorker opens the two anonymous pipes installed as file
// descriptors 3 and 4 by Launch and dispatches the private worker.
func RunInheritedWorker(args []string, stderr io.Writer) int {
	request := os.NewFile(3, "hostpid-ptrace-request")
	response := os.NewFile(4, "hostpid-ptrace-response")
	if request == nil || response == nil {
		fmt.Fprintln(stderr, "[hostpid-ptrace-breakout] inherited worker pipes are unavailable")
		return 1
	}
	defer request.Close()
	defer response.Close()
	return RunWorker(args, request, response, stderr)
}
