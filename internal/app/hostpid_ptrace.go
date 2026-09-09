package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/inguardians/peirates/internal/modules/hostpidptrace"
)

var probeHostPIDPtrace = hostpidptrace.Probe
var runHostPIDPtrace = hostpidptrace.Launch

var launchHostPIDPtraceBreakout = func() error {
	return launchHostPIDPtraceBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

func launchHostPIDPtraceBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	fmt.Fprintln(stdout, "This experimental command runs one bounded command through a disposable child of an explicitly selected process.")
	fmt.Fprintln(stdout, "Eligible means the process matches visible PID 1's observable namespaces and root; it does not prove a physical-host boundary on nested platforms such as Kind.")
	fmt.Fprintln(stderr, "WARNING: ptrace temporarily modifies a live process. A tracer crash, SIGKILL, kernel failure, or node loss can damage, stop, or kill the selected target. Select only a deliberately disposable process.")

	probe, err := probeHostPIDPtrace(context.Background())
	if err != nil {
		return fmt.Errorf("read-only ptrace preflight: %w", err)
	}
	if probe.YamaScope != nil {
		fmt.Fprintf(stdout, "Yama ptrace_scope: %d\n", *probe.YamaScope)
	}
	fmt.Fprintf(stdout, "Current seccomp mode: %d\n", probe.SeccompMode)
	if probe.SecurityLabel != "" {
		fmt.Fprintf(stdout, "Current security label: %s\n", probe.SecurityLabel)
	}
	for _, warning := range probe.Warnings {
		fmt.Fprintf(stderr, "WARNING: %s\n", warning)
	}
	if len(probe.Candidates) == 0 {
		return errors.New("no eligible disposable host process is available")
	}
	fmt.Fprintln(stdout, "Eligible disposable targets:")
	for _, candidate := range probe.Candidates {
		fmt.Fprintf(stdout, "- PID %d  comm=%q  exe=%q  cmd=%q\n",
			candidate.PID, candidate.Comm, candidate.Executable, candidate.CommandLine)
	}

	reader := bufio.NewReader(stdin)
	pidLine, err := readEscapePromptLine(reader, stdout, "Disposable host PID to trace: ")
	if errors.Is(err, io.EOF) {
		return errors.New("breakout cancelled; no process was traced")
	}
	if err != nil {
		return fmt.Errorf("read disposable host PID: %w", err)
	}
	pid, err := strconv.Atoi(pidLine)
	if err != nil || pid <= 1 {
		return errors.New("an explicitly listed disposable PID greater than 1 is required")
	}
	if !candidatePIDPresent(probe.Candidates, pid) {
		return errors.New("selected PID was not in the eligible target list")
	}

	// Re-run the complete read-only qualification after selection. The private
	// worker repeats it once more immediately before PTRACE_SEIZE.
	revalidated, err := probeHostPIDPtrace(context.Background())
	if err != nil {
		return fmt.Errorf("revalidate disposable host PID: %w", err)
	}
	target, ok := candidateByPID(revalidated.Candidates, pid)
	if !ok {
		return errors.New("selected PID is no longer eligible; no process was traced")
	}
	fmt.Fprintf(stdout, "Revalidated PID %d: start=%d state=%c threads=%d tracer=%d core_dumping=%d PID-namespace-depth=%d\n",
		target.PID, target.StartTime, target.State, target.Threads, target.TracerPID, target.CoreDumping, target.PIDDepth)
	fmt.Fprintf(stdout, "UIDs (real/effective/saved/filesystem): %d/%d/%d/%d; root=%d:%d\n",
		target.UIDs[0], target.UIDs[1], target.UIDs[2], target.UIDs[3], target.RootID.Device, target.RootID.Inode)
	namespaceNames := make([]string, 0, len(target.NamespaceIDs))
	for name := range target.NamespaceIDs {
		namespaceNames = append(namespaceNames, name)
	}
	sort.Strings(namespaceNames)
	for _, name := range namespaceNames {
		identity := target.NamespaceIDs[name]
		fmt.Fprintf(stdout, "Namespace %s=%d:%d (matches visible PID 1)\n", name, identity.Device, identity.Inode)
	}
	fmt.Fprintln(stdout, "All required namespace and filesystem-root identities match visible PID 1.")

	command, err := readEscapePromptLine(reader, stdout, "Single host command: ")
	if errors.Is(err, io.EOF) {
		return errors.New("breakout cancelled; no process was traced")
	}
	if err != nil {
		return fmt.Errorf("read host command: %w", err)
	}
	if command == "" {
		return errors.New("a non-empty host command is required")
	}
	if len(command) > hostpidptrace.MaxCommandBytes || strings.IndexByte(command, 0) >= 0 {
		return fmt.Errorf("host command must contain no NUL bytes and be at most %d bytes", hostpidptrace.MaxCommandBytes)
	}
	phrase := hostpidptrace.ConfirmationPhrase(pid)
	confirmation, err := readEscapePromptLine(reader, stdout, "Type "+phrase+" to continue: ")
	if errors.Is(err, io.EOF) || confirmation != phrase {
		return errors.New("breakout cancelled; no process was traced")
	}
	if err != nil {
		return fmt.Errorf("read ptrace confirmation: %w", err)
	}
	fmt.Fprintf(stdout, "[hostpid-ptrace-breakout] tracing disposable host PID %d to run one command in visible PID 1's namespaces\n", pid)
	result, err := runHostPIDPtrace(context.Background(), hostpidptrace.RunOptions{
		Target: target, Command: command,
	})
	if len(result.Output) != 0 {
		if _, writeErr := stdout.Write(result.Output); writeErr != nil && err == nil {
			err = writeErr
		}
		if result.Output[len(result.Output)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
	}
	if result.OutputTruncated {
		fmt.Fprintln(stderr, "WARNING: command output was truncated at the configured limit")
	}
	if result.CommandCompleted {
		fmt.Fprintln(stdout)
		if result.Signal != 0 {
			fmt.Fprintf(stdout, "Host command terminated by signal %d.\n", result.Signal)
		} else {
			fmt.Fprintf(stdout, "Host command exit code: %d\n", result.ExitCode)
		}
	}
	fmt.Fprintf(stdout, "Target restoration: restored=%t detached=%t; output artifact removed=%t\n",
		result.TargetRestored, result.TargetDetached, result.OutputRemoved)
	return err
}

func candidatePIDPresent(candidates []hostpidptrace.Candidate, pid int) bool {
	_, ok := candidateByPID(candidates, pid)
	return ok
}

func candidateByPID(candidates []hostpidptrace.Candidate, pid int) (hostpidptrace.Candidate, bool) {
	for _, candidate := range candidates {
		if candidate.PID == pid {
			return candidate, true
		}
	}
	return hostpidptrace.Candidate{}, false
}
