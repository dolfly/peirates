package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/hostpidptrace"
)

func eligiblePtraceCandidate(pid int) hostpidptrace.Candidate {
	return hostpidptrace.Candidate{
		PID: pid, StartTime: 99, Comm: "sleep", Executable: "/bin/sleep",
		CommandLine: "sleep 300", State: 'S', Threads: 1, PIDDepth: 1,
		NamespaceIDs: map[string]hostpidptrace.Identity{"pid": {Device: 1, Inode: 2}},
		RootID:       hostpidptrace.Identity{Device: 3, Inode: 4},
	}
}

func TestLaunchHostPIDPtraceRequiresExactSelectionAndConfirmation(t *testing.T) {
	originalProbe, originalRun := probeHostPIDPtrace, runHostPIDPtrace
	t.Cleanup(func() { probeHostPIDPtrace, runHostPIDPtrace = originalProbe, originalRun })
	candidate := eligiblePtraceCandidate(123)
	probeHostPIDPtrace = func(context.Context) (hostpidptrace.ProbeResult, error) {
		return hostpidptrace.ProbeResult{Candidates: []hostpidptrace.Candidate{candidate}}, nil
	}
	runs := 0
	runHostPIDPtrace = func(_ context.Context, options hostpidptrace.RunOptions) (hostpidptrace.Result, error) {
		runs++
		if options.Target.PID != 123 || options.Command != "printf marker" {
			t.Fatalf("run options = %#v", options)
		}
		return hostpidptrace.Result{Output: []byte("marker\n"), CommandCompleted: true, ExitCode: 0, TargetRestored: true, TargetDetached: true, OutputRemoved: true}, nil
	}
	input := "123\nprintf marker\n" + hostpidptrace.ConfirmationPhrase(123) + "\n"
	var stdout, stderr bytes.Buffer
	if err := launchHostPIDPtraceBreakoutWithStreams(strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || !strings.Contains(stdout.String(), "marker\n\nHost command exit code: 0\n") || !strings.Contains(stdout.String(), "restored=true detached=true") || !strings.Contains(stderr.String(), "can damage") {
		t.Fatalf("runs=%d stdout=%q stderr=%q", runs, stdout.String(), stderr.String())
	}

	runs = 0
	if err := launchHostPIDPtraceBreakoutWithStreams(strings.NewReader("123\nid\nwrong\n"), io.Discard, io.Discard); err == nil || runs != 0 {
		t.Fatalf("wrong confirmation err=%v runs=%d", err, runs)
	}
}

func TestLaunchHostPIDPtraceFailsClosedWhenTargetChanges(t *testing.T) {
	originalProbe, originalRun := probeHostPIDPtrace, runHostPIDPtrace
	t.Cleanup(func() { probeHostPIDPtrace, runHostPIDPtrace = originalProbe, originalRun })
	calls := 0
	probeHostPIDPtrace = func(context.Context) (hostpidptrace.ProbeResult, error) {
		calls++
		if calls == 1 {
			return hostpidptrace.ProbeResult{Candidates: []hostpidptrace.Candidate{eligiblePtraceCandidate(123)}}, nil
		}
		return hostpidptrace.ProbeResult{}, nil
	}
	runHostPIDPtrace = func(context.Context, hostpidptrace.RunOptions) (hostpidptrace.Result, error) {
		t.Fatal("worker ran after target changed")
		return hostpidptrace.Result{}, nil
	}
	err := launchHostPIDPtraceBreakoutWithStreams(strings.NewReader("123\n"), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no longer eligible") {
		t.Fatalf("error = %v", err)
	}
}

func TestLaunchHostPIDPtraceReportsProbeFailureWithoutTracing(t *testing.T) {
	originalProbe := probeHostPIDPtrace
	t.Cleanup(func() { probeHostPIDPtrace = originalProbe })
	probeHostPIDPtrace = func(context.Context) (hostpidptrace.ProbeResult, error) {
		return hostpidptrace.ProbeResult{}, errors.New("missing CAP_SYS_PTRACE")
	}
	err := launchHostPIDPtraceBreakoutWithStreams(strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "missing CAP_SYS_PTRACE") {
		t.Fatalf("error = %v", err)
	}
}
