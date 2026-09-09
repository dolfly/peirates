//go:build linux && amd64

package hostpidptrace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPatchSyscallTrapPreservesPartialWord(t *testing.T) {
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	patched := patchSyscallTrap(original)
	want := []byte{0x0f, 0x05, 0xcc, 4, 5, 6, 7, 8}
	if !reflect.DeepEqual(patched, want) || !reflect.DeepEqual(original, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("patched=%v original=%v", patched, original)
	}
}

func TestSyscallRegistersUseAMD64ABI(t *testing.T) {
	original := unix.PtraceRegs{Rip: 0x1234, Rsp: 0x5678, Rbx: 9}
	registers := syscallRegisters(original, 77, [6]uint64{1, 2, 3, 4, 5, 6})
	if registers.Rax != 77 || registers.Orig_rax != ^uint64(0) || registers.Rdi != 1 || registers.Rsi != 2 || registers.Rdx != 3 || registers.R10 != 4 || registers.R8 != 5 || registers.R9 != 6 || registers.Rip != original.Rip || registers.Rsp != original.Rsp || registers.Rbx != original.Rbx {
		t.Fatalf("registers = %#v", registers)
	}
}

func TestDecodeSyscallReturn(t *testing.T) {
	if value, err := decodeSyscallReturn(123); err != nil || value != 123 {
		t.Fatalf("success = %d, %v", value, err)
	}
	negativeEPERM := int64(-int64(unix.EPERM))
	if _, err := decodeSyscallReturn(uint64(negativeEPERM)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("errno = %v", err)
	}
	if !allowedRemoteSyscall(unix.SYS_MMAP) || allowedRemoteSyscall(unix.SYS_PTRACE) {
		t.Fatal("remote syscall allowlist is incorrect")
	}
}

func TestPtraceEventDecoding(t *testing.T) {
	stop := unix.WaitStatus((unix.PTRACE_EVENT_STOP << 16) | (int(unix.SIGTRAP) << 8) | 0x7f)
	if err := expectPtraceStop(stop, unix.PTRACE_EVENT_STOP); err != nil {
		t.Fatal(err)
	}
	for _, status := range []unix.WaitStatus{
		unix.WaitStatus((unix.PTRACE_EVENT_FORK << 16) | (int(unix.SIGTRAP) << 8) | 0x7f),
		unix.WaitStatus((unix.PTRACE_EVENT_EXEC << 16) | (int(unix.SIGTRAP) << 8) | 0x7f),
		unix.WaitStatus((unix.PTRACE_EVENT_EXIT << 16) | (int(unix.SIGTRAP) << 8) | 0x7f),
		unix.WaitStatus(int(unix.SIGTERM)),
	} {
		if err := expectTrap(status); err == nil {
			t.Fatalf("unexpected event accepted: %#x", status)
		}
	}
}

func TestRunEngineAgainstOwnedDisposableProcess(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("host /bin/sh is unavailable: %v", err)
	}
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skipf("host /bin/sleep is unavailable: %v", err)
	}

	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	targetPID := command.Process.Pid
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	procPath := filepath.Join("/proc", fmt.Sprintf("%d", targetPID))
	commandLinePath := filepath.Join(procPath, "cmdline")
	var originalCommandLine []byte
	deadline := time.Now().Add(time.Second)
	for len(originalCommandLine) == 0 {
		var err error
		originalCommandLine, err = os.ReadFile(commandLinePath)
		if err != nil {
			t.Fatal(err)
		}
		if len(originalCommandLine) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("disposable target command line did not stabilize")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	statPath := filepath.Join(procPath, "stat")
	originalStat, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, originalStartTime, err := parseStat(originalStat)
	if err != nil {
		t.Fatal(err)
	}
	originalExecutable, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := inspectBoundary(targetPID)
	if err != nil {
		t.Fatal(err)
	}
	target := Candidate{
		PID:          targetPID,
		StartTime:    originalStartTime,
		NamespaceIDs: boundary.namespaces,
		RootID:       boundary.root,
		PIDDepth:     boundary.pidDepth,
	}
	targetFD, err := unix.PidfdOpen(targetPID, 0)
	if err != nil {
		t.Skipf("pidfd_open is unavailable for the disposable target: %v", err)
	}
	artifact, err := createOutputArtifact(targetPID, target.RootID)
	if err != nil {
		_ = unix.Close(targetFD)
		t.Fatal(err)
	}

	runtime.LockOSThread()
	result, err := runEngine(context.Background(), RunOptions{
		Target: target, Command: "printf peirates-owned-ptrace-ok",
		Timeout: 5 * time.Second, OutputLimit: 4096,
	}, target, targetFD, artifact)
	runtime.UnlockOSThread()
	if err != nil {
		if strings.Contains(err.Error(), "PTRACE_SEIZE target") &&
			(errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
			t.Skipf("ptrace attach to a test-owned child is blocked by current kernel, LSM, or sandbox policy: %v", err)
		}
		t.Fatal(err)
	}
	if !result.CommandCompleted || result.ExitCode != 0 || result.Signal != 0 {
		t.Fatalf("command result = %#v", result)
	}
	if string(result.Output) != "peirates-owned-ptrace-ok" || result.OutputTruncated {
		t.Fatalf("command output = %q, truncated=%t", result.Output, result.OutputTruncated)
	}
	if !result.TargetRestored || !result.TargetDetached || !result.OutputRemoved {
		t.Fatalf("cleanup result = %#v", result)
	}

	currentStat, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatalf("disposable target did not survive: %v", err)
	}
	_, _, _, currentStartTime, err := parseStat(currentStat)
	if err != nil {
		t.Fatal(err)
	}
	currentExecutable, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		t.Fatal(err)
	}
	currentCommandLine, err := os.ReadFile(commandLinePath)
	if err != nil {
		t.Fatal(err)
	}
	if currentStartTime != originalStartTime || currentExecutable != originalExecutable || !bytes.Equal(currentCommandLine, originalCommandLine) {
		t.Fatalf("disposable target identity changed: start=%d/%d exe=%q/%q cmdline=%q/%q",
			originalStartTime, currentStartTime, originalExecutable, currentExecutable,
			originalCommandLine, currentCommandLine)
	}
}

type cleanupTrace struct {
	operations    []string
	continuedWith []int
	registers     unix.PtraceRegs
	word          []byte
	waits         []unix.WaitStatus
}

func (fake *cleanupTrace) record(value string) { fake.operations = append(fake.operations, value) }
func (fake *cleanupTrace) seize(int) error     { fake.record("seize"); return nil }
func (fake *cleanupTrace) interrupt(int) error { fake.record("interrupt"); return nil }
func (fake *cleanupTrace) wait(context.Context, int, time.Duration) (waitResult, error) {
	fake.record("wait")
	if len(fake.waits) != 0 {
		status := fake.waits[0]
		fake.waits = fake.waits[1:]
		return waitResult{status: status}, nil
	}
	return waitResult{status: unix.WaitStatus(int(unix.SIGKILL))}, nil
}
func (fake *cleanupTrace) getRegs(int) (unix.PtraceRegs, error) {
	fake.record("get-regs")
	return fake.registers, nil
}
func (fake *cleanupTrace) setRegs(int, unix.PtraceRegs) error {
	fake.record("restore-regs")
	return nil
}
func (fake *cleanupTrace) peek(_ int, _ uintptr, output []byte) error {
	fake.record("verify-word")
	copy(output, fake.word)
	return nil
}
func (fake *cleanupTrace) poke(_ int, _ uintptr, data []byte) error {
	fake.record("restore-word")
	fake.word = append([]byte(nil), data...)
	return nil
}
func (fake *cleanupTrace) setOptions(int, int) error { return nil }
func (fake *cleanupTrace) cont(_ int, signal int) error {
	fake.record("continue-child")
	fake.continuedWith = append(fake.continuedWith, signal)
	return nil
}
func (fake *cleanupTrace) eventMessage(int) (uint, error) { return 0, nil }
func (fake *cleanupTrace) detach(int, int) error          { fake.record("detach-target"); return nil }
func (fake *cleanupTrace) pidfdOpen(int) (int, error)     { fake.record("pidfd-open"); return 88, nil }
func (fake *cleanupTrace) pidfdAlive(int) error           { fake.record("pidfd-alive"); return nil }
func (fake *cleanupTrace) pidfdKill(int) error            { fake.record("pidfd-kill-child"); return nil }
func (fake *cleanupTrace) close(int) error                { fake.record("close-pidfd"); return nil }

func TestCleanupKillsPidfdChildBeforeRestoringAndDetachingTarget(t *testing.T) {
	api := &cleanupTrace{registers: unix.PtraceRegs{Rip: 123}, word: []byte("original")}
	state := &engine{
		api: api, ctx: context.Background(), target: Candidate{PID: 44}, targetFD: 77,
		stage: stageChildContained, savedRegs: api.registers, haveSavedRegs: true,
		savedWord: []byte("original"), patchAttempted: true, childPID: 55, childFD: 88,
		childStopped: true,
	}
	var result Result
	if err := state.cleanup(&result); err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"pidfd-kill-child", "continue-child", "wait", "restore-word", "verify-word", "restore-regs", "get-regs", "detach-target"}
	if !containsOrdered(api.operations, wantOrder) {
		t.Fatalf("cleanup operations = %#v, want ordered %#v", api.operations, wantOrder)
	}
	if !result.TargetRestored || !result.TargetDetached {
		t.Fatalf("cleanup result = %#v", result)
	}
}

func TestWaitChildContinuesExecEventsAndReinjectsSignals(t *testing.T) {
	signalStop := unix.WaitStatus((int(unix.SIGCHLD) << 8) | 0x7f)
	execStop := unix.WaitStatus((unix.PTRACE_EVENT_EXEC << 16) | (int(unix.SIGTRAP) << 8) | 0x7f)
	exitStop := unix.WaitStatus((unix.PTRACE_EVENT_EXIT << 16) | (int(unix.SIGTRAP) << 8) | 0x7f)
	api := &cleanupTrace{waits: []unix.WaitStatus{signalStop, execStop, exitStop, 0}}
	state := &engine{
		api: api, ctx: context.Background(), childPID: 55, childFD: 88,
		stage: stageChildExeced,
	}
	result, err := state.waitChild(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CommandCompleted || result.ExitCode != 0 || state.stage != stageChildReaped {
		t.Fatalf("result=%#v stage=%s", result, state.stage)
	}
	wantSignals := []int{0, int(unix.SIGCHLD), 0, 0}
	if !reflect.DeepEqual(api.continuedWith, wantSignals) {
		t.Fatalf("continued with signals %#v, want %#v", api.continuedWith, wantSignals)
	}
}

func TestCleanupNeverFallsBackToRawPIDSignal(t *testing.T) {
	api := &cleanupTrace{registers: unix.PtraceRegs{Rip: 123}}
	state := &engine{api: api, ctx: context.Background(), target: Candidate{PID: 44}, targetFD: -1, stage: stageTargetDetached, childPID: 55, childFD: -1}
	if err := state.cleanup(&Result{}); err != nil {
		t.Fatal(err)
	}
	if !containsOrdered(api.operations, []string{"pidfd-open", "pidfd-kill-child"}) {
		t.Fatalf("cleanup operations = %#v", api.operations)
	}
}

func TestCleanupHandlesEveryMutationStage(t *testing.T) {
	ptraceStop := unix.WaitStatus((unix.PTRACE_EVENT_STOP << 16) | (int(unix.SIGTRAP) << 8) | 0x7f)
	for _, stage := range []mutationStage{
		stageOutputCreated, stageTargetSeized, stageTargetStopped, stageTargetPatched,
		stageChildCreated, stageChildContained, stageTargetRestored,
		stageTargetDetached, stageChildExeced, stageChildReaped,
	} {
		t.Run(stage.String(), func(t *testing.T) {
			api := &cleanupTrace{registers: unix.PtraceRegs{Rip: 123}, word: []byte("original")}
			state := &engine{api: api, ctx: context.Background(), target: Candidate{PID: 44}, targetFD: 77, childFD: -1, stage: stage}
			if stage == stageTargetSeized {
				api.waits = []unix.WaitStatus{ptraceStop}
			}
			if stage >= stageTargetStopped && stage < stageTargetRestored {
				state.savedRegs, state.haveSavedRegs = api.registers, true
			}
			if stage >= stageTargetPatched && stage < stageTargetRestored {
				state.savedWord, state.patchAttempted = []byte("original"), true
			}
			if stage >= stageChildCreated && stage < stageChildReaped {
				state.childPID, state.childFD, state.childStopped = 55, 88, true
			}
			if stage >= stageChildReaped {
				state.childPID, state.childFD, state.childReaped = 55, 88, true
			}
			var result Result
			if err := state.cleanup(&result); err != nil {
				t.Fatalf("cleanup stage %s: %v", stage, err)
			}
			if stage >= stageTargetSeized && (!result.TargetRestored || !result.TargetDetached) {
				t.Fatalf("stage %s result = %#v", stage, result)
			}
		})
	}
}

func TestOutputArtifactReadEnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture")
	if err := os.WriteFile(path, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	artifact := &outputArtifact{fileFD: fd}
	output, truncated, err := artifact.read(4)
	if err != nil || string(output) != "0123" || !truncated {
		t.Fatalf("read = %q, %t, %v", output, truncated, err)
	}
}

func TestOutputArtifactRemovalRefusesIdentityChange(t *testing.T) {
	directory := t.TempDir()
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	name := "capture"
	fd, err := unix.Openat(dirFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	artifact := &outputArtifact{tmpFD: dirFD, fileFD: fd, name: name, id: Identity{Device: uint64(stat.Dev), Inode: stat.Ino}}
	if err := unix.Unlinkat(dirFD, name, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := artifact.remove(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("identity-safe removal error = %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(directory, name)); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement file changed: %q, %v", data, err)
	}
}

func containsOrdered(actual, wanted []string) bool {
	index := 0
	for _, operation := range actual {
		if index < len(wanted) && operation == wanted[index] {
			index++
		}
	}
	return index == len(wanted)
}
