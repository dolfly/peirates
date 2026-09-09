//go:build linux && amd64

package hostpidptrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	workerRequestFD  = 3
	workerResponseFD = 4
	scratchSize      = 64 * 1024
	syscallTimeout   = 3 * time.Second
)

type mutationStage uint8

const (
	stageQualified mutationStage = iota
	stageTargetSeized
	stageTargetStopped
	stageTargetPatched
	stageChildCreated
	stageChildContained
	stageTargetRestored
	stageTargetDetached
	stageChildExeced
	stageChildReaped
)

func (stage mutationStage) String() string {
	names := [...]string{
		"qualified", "target-seized", "target-stopped",
		"target-patched", "child-created", "child-contained", "target-restored",
		"target-detached", "child-execed", "child-reaped",
	}
	if int(stage) >= len(names) {
		return "unknown"
	}
	return names[stage]
}

type waitResult struct {
	pid    int
	status unix.WaitStatus
}

type tracePlatform interface {
	seize(int) error
	interrupt(int) error
	wait(context.Context, int, time.Duration) (waitResult, error)
	getRegs(int) (unix.PtraceRegs, error)
	setRegs(int, unix.PtraceRegs) error
	peek(int, uintptr, []byte) error
	poke(int, uintptr, []byte) error
	setOptions(int, int) error
	cont(int, int) error
	eventMessage(int) (uint, error)
	detach(int, int) error
	pidfdOpen(int) (int, error)
	pidfdAlive(int) error
	pidfdKill(int) error
	close(int) error
}

type unixTracePlatform struct{}

func (unixTracePlatform) seize(pid int) error     { return unix.PtraceSeize(pid) }
func (unixTracePlatform) interrupt(pid int) error { return unix.PtraceInterrupt(pid) }
func (unixTracePlatform) getRegs(pid int) (unix.PtraceRegs, error) {
	var registers unix.PtraceRegs
	err := unix.PtraceGetRegs(pid, &registers)
	return registers, err
}
func (unixTracePlatform) setRegs(pid int, registers unix.PtraceRegs) error {
	return unix.PtraceSetRegs(pid, &registers)
}
func (unixTracePlatform) peek(pid int, address uintptr, output []byte) error {
	read, err := unix.PtracePeekText(pid, address, output)
	if err != nil {
		return err
	}
	if read != len(output) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (unixTracePlatform) poke(pid int, address uintptr, data []byte) error {
	written, err := unix.PtracePokeText(pid, address, data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
func (unixTracePlatform) setOptions(pid, options int) error {
	return unix.PtraceSetOptions(pid, options)
}
func (unixTracePlatform) cont(pid, signal int) error { return unix.PtraceCont(pid, signal) }
func (unixTracePlatform) eventMessage(pid int) (uint, error) {
	return unix.PtraceGetEventMsg(pid)
}
func (unixTracePlatform) detach(pid, signal int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func (unixTracePlatform) pidfdOpen(pid int) (int, error) { return unix.PidfdOpen(pid, 0) }
func (unixTracePlatform) pidfdAlive(pidfd int) error {
	return unix.PidfdSendSignal(pidfd, 0, nil, 0)
}
func (unixTracePlatform) pidfdKill(pidfd int) error {
	return unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
}
func (unixTracePlatform) close(fd int) error { return unix.Close(fd) }

func (unixTracePlatform) wait(ctx context.Context, pid int, timeout time.Duration) (waitResult, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		var status unix.WaitStatus
		waited, err := unix.Wait4(pid, &status, unix.WNOHANG|unix.WALL, nil)
		if err != nil {
			return waitResult{}, err
		}
		if waited != 0 {
			return waitResult{pid: waited, status: status}, nil
		}
		if err := ctx.Err(); err != nil {
			return waitResult{}, err
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return waitResult{}, context.DeadlineExceeded
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type payloadLayout struct {
	data        []byte
	name        uint64
	root        uint64
	terminal    uint64
	shell       uint64
	argv        uint64
	environment uint64
}

type payloadBuilder struct {
	base uint64
	data []byte
}

func (builder *payloadBuilder) align() {
	for len(builder.data)%8 != 0 {
		builder.data = append(builder.data, 0)
	}
}

func (builder *payloadBuilder) string(value string) uint64 {
	address := builder.base + uint64(len(builder.data))
	builder.data = append(builder.data, value...)
	builder.data = append(builder.data, 0)
	return address
}

func (builder *payloadBuilder) pointers(values ...uint64) uint64 {
	builder.align()
	address := builder.base + uint64(len(builder.data))
	for _, value := range values {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], value)
		builder.data = append(builder.data, encoded[:]...)
	}
	return address
}

func buildPayload(base uint64, terminalPath string) (payloadLayout, error) {
	builder := payloadBuilder{base: base}
	name := builder.string("peirates-host")
	root := builder.string("/")
	terminal := builder.string(terminalPath)
	shell := builder.string("/bin/sh")
	argv0 := builder.string("sh")
	argv1 := builder.string("-i")
	environmentValues := []string{
		"HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/sh",
		"TERM=xterm-256color",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	var environmentPointers []uint64
	for _, value := range environmentValues {
		environmentPointers = append(environmentPointers, builder.string(value))
	}
	argv := builder.pointers(argv0, argv1, 0)
	environmentPointers = append(environmentPointers, 0)
	environment := builder.pointers(environmentPointers...)
	if len(builder.data) > scratchSize {
		return payloadLayout{}, errors.New("internal interactive-shell payload exceeds scratch mapping")
	}
	return payloadLayout{
		data: builder.data, name: name, root: root, terminal: terminal,
		shell: shell, argv: argv, environment: environment,
	}, nil
}

type engine struct {
	api      tracePlatform
	ctx      context.Context
	target   Candidate
	targetFD int
	stage    mutationStage

	savedRegs      unix.PtraceRegs
	haveSavedRegs  bool
	savedWord      []byte
	patchAttempted bool
	patchAddress   uintptr
	pendingSignal  int
	scratch        uint64

	childPID     int
	childFD      int
	childStopped bool
	childReaped  bool
}

func runEngine(ctx context.Context, options RunOptions, target Candidate, targetFD int) (Result, error) {
	state := &engine{
		api: unixTracePlatform{}, ctx: ctx, target: target, targetFD: targetFD,
		stage: stageQualified, childFD: -1,
	}
	result, operationErr := state.execute(options)
	cleanupErr := state.cleanup(&result)
	result.Stage = state.stage.String()
	if cleanupErr != nil {
		return result, cleanupErr
	}
	return result, operationErr
}

func (state *engine) execute(options RunOptions) (Result, error) {
	if err := state.ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := state.api.pidfdAlive(state.targetFD); err != nil {
		return Result{}, fmt.Errorf("confirmed target pidfd is no longer live: %w", err)
	}
	if err := state.api.seize(state.target.PID); err != nil {
		return Result{}, fmt.Errorf("PTRACE_SEIZE target: %w", err)
	}
	state.stage = stageTargetSeized
	if err := state.api.pidfdAlive(state.targetFD); err != nil {
		return Result{}, fmt.Errorf("confirmed target exited during PTRACE_SEIZE: %w", err)
	}
	if err := state.api.interrupt(state.target.PID); err != nil {
		return Result{}, fmt.Errorf("PTRACE_INTERRUPT target: %w", err)
	}
	stop, err := state.api.wait(state.ctx, state.target.PID, syscallTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("wait for target interrupt stop: %w", err)
	}
	if err := expectPtraceStop(stop.status, unix.PTRACE_EVENT_STOP); err != nil {
		if stop.status.Stopped() && stop.status.StopSignal() != unix.SIGTRAP {
			state.pendingSignal = int(stop.status.StopSignal())
		}
		return Result{}, fmt.Errorf("target interrupt stop: %w", err)
	}
	state.stage = stageTargetStopped
	if err := state.api.pidfdAlive(state.targetFD); err != nil {
		return Result{}, fmt.Errorf("confirmed target exited before snapshot: %w", err)
	}
	state.savedRegs, err = state.api.getRegs(state.target.PID)
	if err != nil {
		return Result{}, fmt.Errorf("read target registers: %w", err)
	}
	state.haveSavedRegs = true
	if err := verifyPrivateExecutableMapping(state.target.PID, state.savedRegs.Rip); err != nil {
		return Result{}, err
	}
	state.patchAddress = uintptr(state.savedRegs.Rip)
	state.savedWord = make([]byte, 8)
	if err := state.api.peek(state.target.PID, state.patchAddress, state.savedWord); err != nil {
		return Result{}, fmt.Errorf("read target instruction word: %w", err)
	}
	verified := make([]byte, len(state.savedWord))
	if err := state.api.peek(state.target.PID, state.patchAddress, verified); err != nil || !bytes.Equal(verified, state.savedWord) {
		return Result{}, errors.New("target instruction word could not be verified")
	}
	patched := patchSyscallTrap(state.savedWord)
	state.patchAttempted = true
	if err := state.api.poke(state.target.PID, state.patchAddress, patched); err != nil {
		return Result{}, fmt.Errorf("patch target instruction word: %w", err)
	}
	if err := state.api.peek(state.target.PID, state.patchAddress, verified); err != nil || !bytes.Equal(verified, patched) {
		return Result{}, errors.New("patched target instruction word could not be verified")
	}
	state.stage = stageTargetPatched
	if err := state.api.setOptions(state.target.PID, unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return Result{}, fmt.Errorf("set target ptrace options: %w", err)
	}

	mapping, err := state.remoteSyscall(state.target.PID, unix.SYS_MMAP, [6]uint64{
		0, scratchSize, unix.PROT_READ | unix.PROT_WRITE,
		unix.MAP_PRIVATE | unix.MAP_ANONYMOUS, ^uint64(0), 0,
	})
	if err != nil {
		return Result{}, fmt.Errorf("allocate target scratch mapping: %w", err)
	}
	state.scratch = mapping
	payload, err := buildPayload(mapping, fmt.Sprintf("/dev/pts/%d", options.Terminal.Number))
	if err != nil {
		return Result{}, err
	}
	if err := writeAndVerify(state.api, state.target.PID, uintptr(mapping), payload.data); err != nil {
		return Result{}, fmt.Errorf("write target scratch mapping: %w", err)
	}
	if err := state.remoteClone(); err != nil {
		return Result{}, err
	}
	if err := state.api.setOptions(state.childPID, unix.PTRACE_O_EXITKILL|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT); err != nil {
		return Result{}, fmt.Errorf("contain injected child: %w", err)
	}
	if err := verifyChildIdentity(state.childPID, state.target); err != nil {
		return Result{}, err
	}
	state.stage = stageChildContained
	if _, err := state.remoteSyscall(state.target.PID, unix.SYS_MUNMAP, [6]uint64{mapping, scratchSize}); err != nil {
		return Result{}, fmt.Errorf("unmap scratch from original target: %w", err)
	}
	state.scratch = 0
	if err := state.restoreTarget(); err != nil {
		return Result{}, err
	}
	state.stage = stageTargetRestored
	if err := state.api.detach(state.target.PID, state.pendingSignal); err != nil {
		return Result{}, fmt.Errorf("detach restored target: %w", err)
	}
	state.stage = stageTargetDetached

	if err := state.advanceChildFromClone(); err != nil {
		return Result{}, err
	}
	if err := state.configureChild(payload); err != nil {
		state.exitChild(126)
		return Result{}, err
	}
	if err := state.execChild(payload); err != nil {
		state.exitChild(127)
		return Result{}, err
	}
	state.stage = stageChildExeced
	return state.waitChild()
}

func (state *engine) remoteSyscall(pid int, number uint64, args [6]uint64) (uint64, error) {
	if !allowedRemoteSyscall(number) {
		return 0, fmt.Errorf("remote syscall %d is not allowed", number)
	}
	registers := syscallRegisters(state.savedRegs, number, args)
	if err := state.api.setRegs(pid, registers); err != nil {
		return 0, err
	}
	if err := state.api.cont(pid, 0); err != nil {
		return 0, err
	}
	stop, err := state.api.wait(state.ctx, pid, syscallTimeout)
	if err != nil {
		return 0, err
	}
	if err := expectTrap(stop.status); err != nil {
		if pid == state.target.PID && stop.status.Stopped() && stop.status.StopSignal() != unix.SIGTRAP {
			state.pendingSignal = int(stop.status.StopSignal())
		}
		return 0, err
	}
	result, err := state.api.getRegs(pid)
	if err != nil {
		return 0, err
	}
	return decodeSyscallReturn(result.Rax)
}

func (state *engine) remoteClone() error {
	flags := uint64(unix.CLONE_PARENT | unix.SIGCHLD)
	registers := syscallRegisters(state.savedRegs, unix.SYS_CLONE, [6]uint64{flags})
	if err := state.api.setRegs(state.target.PID, registers); err != nil {
		return err
	}
	if err := state.api.cont(state.target.PID, 0); err != nil {
		return err
	}
	event, err := state.api.wait(state.ctx, state.target.PID, syscallTimeout)
	if err != nil {
		return fmt.Errorf("wait for child creation event: %w", err)
	}
	cause := event.status.TrapCause()
	if !event.status.Stopped() || event.status.StopSignal() != unix.SIGTRAP || (cause != unix.PTRACE_EVENT_FORK && cause != unix.PTRACE_EVENT_CLONE) {
		if event.status.Stopped() && event.status.StopSignal() != unix.SIGTRAP {
			state.pendingSignal = int(event.status.StopSignal())
		}
		return errors.New("unexpected ptrace event while creating child")
	}
	message, err := state.api.eventMessage(state.target.PID)
	if err != nil || message <= 1 {
		return errors.New("ptrace child event did not return a valid PID")
	}
	childPID := int(message)
	state.childPID = childPID
	state.stage = stageChildCreated
	state.childFD, err = state.api.pidfdOpen(childPID)
	if err != nil {
		return fmt.Errorf("open injected child pidfd: %w", err)
	}
	childStop, err := state.api.wait(state.ctx, childPID, syscallTimeout)
	if err != nil || !childStop.status.Stopped() {
		return errors.New("injected child did not enter its initial ptrace stop")
	}
	state.childStopped = true
	if err := state.api.cont(state.target.PID, 0); err != nil {
		return err
	}
	trap, err := state.api.wait(state.ctx, state.target.PID, syscallTimeout)
	if err != nil || expectTrap(trap.status) != nil {
		if err == nil && trap.status.Stopped() && trap.status.StopSignal() != unix.SIGTRAP {
			state.pendingSignal = int(trap.status.StopSignal())
		}
		return errors.New("original target did not complete clone syscall")
	}
	result, err := state.api.getRegs(state.target.PID)
	if err != nil {
		return err
	}
	returned, err := decodeSyscallReturn(result.Rax)
	if err != nil || int(returned) != childPID {
		return errors.New("clone return PID did not match ptrace event PID")
	}
	return nil
}

func (state *engine) restoreTarget() error {
	if state.patchAttempted && len(state.savedWord) != 0 {
		if err := state.api.poke(state.target.PID, state.patchAddress, state.savedWord); err != nil {
			return fmt.Errorf("restore target instruction word: %w", err)
		}
		verified := make([]byte, len(state.savedWord))
		if err := state.api.peek(state.target.PID, state.patchAddress, verified); err != nil || !bytes.Equal(verified, state.savedWord) {
			return errors.New("restored target instruction word could not be verified; target may be damaged")
		}
	}
	if state.haveSavedRegs {
		if err := state.api.setRegs(state.target.PID, state.savedRegs); err != nil {
			return fmt.Errorf("restore target registers: %w", err)
		}
		verifiedRegisters, err := state.api.getRegs(state.target.PID)
		if err != nil || !reflect.DeepEqual(verifiedRegisters, state.savedRegs) {
			return errors.New("restored target registers could not be verified; target may be damaged")
		}
	}
	return nil
}

func (state *engine) advanceChildFromClone() error {
	if err := state.api.cont(state.childPID, 0); err != nil {
		return fmt.Errorf("continue injected child from clone: %w", err)
	}
	stop, err := state.api.wait(state.ctx, state.childPID, syscallTimeout)
	if err != nil || expectTrap(stop.status) != nil {
		return errors.New("injected child did not reach its syscall trap")
	}
	state.childStopped = true
	return nil
}

func (state *engine) childSyscall(number uint64, arguments [6]uint64) (uint64, error) {
	return state.remoteSyscall(state.childPID, number, arguments)
}

func (state *engine) configureChild(payload payloadLayout) error {
	currentDirectory := int64(unix.AT_FDCWD)
	if _, err := state.childSyscall(unix.SYS_PRCTL, [6]uint64{unix.PR_SET_NAME, payload.name}); err != nil {
		return fmt.Errorf("set child process name: %w", err)
	}
	if _, err := state.childSyscall(unix.SYS_CHDIR, [6]uint64{payload.root}); err != nil {
		return fmt.Errorf("change child directory: %w", err)
	}
	if _, err := state.childSyscall(unix.SYS_SETSID, [6]uint64{}); err != nil {
		return fmt.Errorf("create child terminal session: %w", err)
	}
	terminalFD, err := state.childSyscall(unix.SYS_OPENAT, [6]uint64{uint64(currentDirectory), payload.terminal, unix.O_RDWR | unix.O_NOCTTY})
	if err != nil {
		return fmt.Errorf("open child PTY slave: %w", err)
	}
	if _, err := state.childSyscall(unix.SYS_IOCTL, [6]uint64{terminalFD, unix.TIOCSCTTY, 0}); err != nil {
		return fmt.Errorf("make PTY the child controlling terminal: %w", err)
	}
	for _, targetFD := range []uint64{0, 1, 2} {
		if terminalFD == targetFD {
			continue
		}
		if _, err := state.childSyscall(unix.SYS_DUP3, [6]uint64{terminalFD, targetFD, 0}); err != nil {
			return fmt.Errorf("redirect child descriptor %d: %w", targetFD, err)
		}
	}
	if terminalFD > 2 {
		if _, err := state.childSyscall(unix.SYS_CLOSE, [6]uint64{terminalFD}); err != nil {
			return fmt.Errorf("close child descriptor: %w", err)
		}
	}
	return nil
}

func (state *engine) execChild(payload payloadLayout) error {
	registers := syscallRegisters(state.savedRegs, unix.SYS_EXECVE, [6]uint64{payload.shell, payload.argv, payload.environment})
	if err := state.api.setRegs(state.childPID, registers); err != nil {
		return err
	}
	if err := state.api.cont(state.childPID, 0); err != nil {
		return err
	}
	event, err := state.api.wait(state.ctx, state.childPID, syscallTimeout)
	if err != nil {
		return fmt.Errorf("wait for child exec: %w", err)
	}
	if !event.status.Stopped() || event.status.StopSignal() != unix.SIGTRAP || event.status.TrapCause() != unix.PTRACE_EVENT_EXEC {
		return errors.New("child failed to exec host /bin/sh")
	}
	state.childStopped = true
	return nil
}

func (state *engine) waitChild() (Result, error) {
	if err := state.api.cont(state.childPID, 0); err != nil {
		return Result{}, err
	}
	state.childStopped = false
	for {
		event, err := state.api.wait(state.ctx, state.childPID, 0)
		if err != nil {
			return Result{}, fmt.Errorf("wait for interactive host shell: %w", err)
		}
		status := event.status
		if status.Exited() {
			state.childReaped = true
			state.stage = stageChildReaped
			return Result{ShellExited: true, ExitCode: status.ExitStatus(), TargetRestored: true, TargetDetached: true}, nil
		}
		if status.Signaled() {
			state.childReaped = true
			state.stage = stageChildReaped
			return Result{ShellExited: true, ExitCode: -1, Signal: int(status.Signal()), TargetRestored: true, TargetDetached: true}, nil
		}
		if status.Stopped() && status.TrapCause() == unix.PTRACE_EVENT_EXIT {
			state.childStopped = true
			if err := state.api.cont(state.childPID, 0); err != nil {
				return Result{}, err
			}
			state.childStopped = false
			continue
		}
		if status.Stopped() && status.TrapCause() == unix.PTRACE_EVENT_EXEC {
			state.childStopped = true
			if err := state.api.cont(state.childPID, 0); err != nil {
				return Result{}, err
			}
			state.childStopped = false
			continue
		}
		if status.Stopped() && status.TrapCause() <= 0 {
			state.childStopped = true
			if err := state.api.cont(state.childPID, int(status.StopSignal())); err != nil {
				return Result{}, err
			}
			state.childStopped = false
			continue
		}
		return Result{}, fmt.Errorf("unexpected injected-child ptrace event %#x", uint32(status))
	}
}

func (state *engine) exitChild(code int) {
	registers := syscallRegisters(state.savedRegs, unix.SYS_EXIT_GROUP, [6]uint64{uint64(code)})
	if state.api.setRegs(state.childPID, registers) == nil && state.api.cont(state.childPID, 0) == nil {
		state.childStopped = false
		if event, err := state.api.wait(context.Background(), state.childPID, syscallTimeout); err == nil && event.status.Exited() {
			state.childReaped = true
		}
	}
}

func (state *engine) cleanup(result *Result) error {
	var failures []string
	result.TargetRestored = state.stage >= stageTargetRestored
	result.TargetDetached = state.stage >= stageTargetDetached
	if state.childPID > 1 && !state.childReaped {
		if state.childFD < 0 {
			state.childFD, _ = state.api.pidfdOpen(state.childPID)
		}
		if state.childFD < 0 {
			failures = append(failures, "child exists without pidfd; refusing numeric-PID cleanup")
		} else {
			if err := state.api.pidfdKill(state.childFD); err != nil && !errors.Is(err, unix.ESRCH) {
				failures = append(failures, "kill injected child through pidfd: "+err.Error())
			}
			if state.childStopped {
				_ = state.api.cont(state.childPID, 0)
			}
			if err := state.reapKilledChild(); err != nil {
				failures = append(failures, "reap injected child: "+err.Error())
			}
		}
	}
	if state.stage == stageTargetSeized {
		if err := state.api.interrupt(state.target.PID); err == nil {
			if stop, waitErr := state.api.wait(context.Background(), state.target.PID, syscallTimeout); waitErr == nil && stop.status.Stopped() {
				state.stage = stageTargetStopped
			}
		}
	}
	if state.scratch != 0 && state.stage >= stageTargetPatched && state.stage < stageTargetRestored {
		originalContext := state.ctx
		state.ctx = context.Background()
		if _, err := state.remoteSyscall(state.target.PID, unix.SYS_MUNMAP, [6]uint64{state.scratch, scratchSize}); err != nil {
			failures = append(failures, "unmap original-target scratch during cleanup: "+err.Error())
		} else {
			state.scratch = 0
		}
		state.ctx = originalContext
	}
	if state.stage >= stageTargetStopped && state.stage < stageTargetRestored {
		if err := state.restoreTarget(); err != nil {
			failures = append(failures, err.Error())
		} else {
			state.stage = stageTargetRestored
			result.TargetRestored = true
		}
	}
	if state.stage >= stageTargetSeized && state.stage < stageTargetDetached {
		if err := state.api.detach(state.target.PID, state.pendingSignal); err != nil {
			failures = append(failures, "detach original target: "+err.Error())
		} else {
			state.stage = stageTargetDetached
			result.TargetDetached = true
		}
	}
	if state.targetFD >= 0 {
		_ = state.api.close(state.targetFD)
		state.targetFD = -1
	}
	if state.childFD >= 0 {
		_ = state.api.close(state.childFD)
		state.childFD = -1
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (state *engine) reapKilledChild() error {
	for attempts := 0; attempts < 4; attempts++ {
		event, err := state.api.wait(context.Background(), state.childPID, syscallTimeout)
		if errors.Is(err, unix.ECHILD) {
			state.childReaped = true
			return nil
		}
		if err != nil {
			return err
		}
		if event.status.Exited() || event.status.Signaled() {
			state.childReaped = true
			return nil
		}
		if event.status.Stopped() {
			if err := state.api.cont(state.childPID, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
			continue
		}
		return errors.New("unexpected wait status during child cleanup")
	}
	return errors.New("injected child did not reach a terminal wait status")
}

func patchSyscallTrap(original []byte) []byte {
	patched := append([]byte(nil), original...)
	copy(patched, []byte{0x0f, 0x05, 0xcc})
	return patched
}

func syscallRegisters(original unix.PtraceRegs, number uint64, arguments [6]uint64) unix.PtraceRegs {
	registers := original
	registers.Rax = number
	registers.Orig_rax = ^uint64(0)
	registers.Rdi = arguments[0]
	registers.Rsi = arguments[1]
	registers.Rdx = arguments[2]
	registers.R10 = arguments[3]
	registers.R8 = arguments[4]
	registers.R9 = arguments[5]
	registers.Rip = original.Rip
	return registers
}

func decodeSyscallReturn(value uint64) (uint64, error) {
	signed := int64(value)
	if signed < 0 && signed >= -4095 {
		return 0, syscall.Errno(-signed)
	}
	return value, nil
}

func allowedRemoteSyscall(number uint64) bool {
	switch number {
	case unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_CLONE, unix.SYS_PRCTL,
		unix.SYS_CHDIR, unix.SYS_SETSID, unix.SYS_OPENAT, unix.SYS_IOCTL,
		unix.SYS_DUP3, unix.SYS_CLOSE, unix.SYS_EXECVE, unix.SYS_EXIT_GROUP:
		return true
	default:
		return false
	}
}

func writeAndVerify(api tracePlatform, pid int, address uintptr, data []byte) error {
	for offset := 0; offset < len(data); offset += 8 {
		end := offset + 8
		word := make([]byte, 8)
		if end > len(data) {
			end = len(data)
		}
		copy(word, data[offset:end])
		if err := api.poke(pid, address+uintptr(offset), word); err != nil {
			return err
		}
		verified := make([]byte, 8)
		if err := api.peek(pid, address+uintptr(offset), verified); err != nil {
			return err
		}
		if !bytes.Equal(word, verified) {
			return errors.New("remote memory verification failed")
		}
	}
	return nil
}

func expectPtraceStop(status unix.WaitStatus, cause int) error {
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP || status.TrapCause() != cause {
		return fmt.Errorf("unexpected wait status %#x", uint32(status))
	}
	return nil
}

func expectTrap(status unix.WaitStatus) error {
	return expectPtraceStop(status, 0)
}

func verifyPrivateExecutableMapping(pid int, instructionPointer uint64) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return fmt.Errorf("read target memory mappings: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "r-xp" {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		end, endErr := strconv.ParseUint(bounds[1], 16, 64)
		if startErr == nil && endErr == nil && instructionPointer >= start && instructionPointer+8 <= end {
			return nil
		}
	}
	return errors.New("target instruction pointer is not within a private executable user mapping")
}

func verifyChildIdentity(pid int, target Candidate) error {
	boundary, err := inspectBoundary(pid)
	if err != nil {
		return fmt.Errorf("inspect injected child identity: %w", err)
	}
	if boundary.root != target.RootID || boundary.pidDepth != target.PIDDepth || !identityMapsEqual(boundary.namespaces, target.NamespaceIDs) {
		return errors.New("injected child namespace or root identity differs from the selected target")
	}
	return nil
}

func launchWorker(ctx context.Context, options RunOptions, input io.Reader, output io.Writer, terminalFD int, master *os.File) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		return Result{}, fmt.Errorf("create worker request pipe: %w", err)
	}
	defer requestWrite.Close()
	responseRead, responseWrite, err := os.Pipe()
	if err != nil {
		requestRead.Close()
		return Result{}, fmt.Errorf("create worker response pipe: %w", err)
	}
	defer responseRead.Close()
	command := exec.Command("/proc/self/exe", WorkerArgument)
	command.ExtraFiles = []*os.File{requestRead, responseWrite}
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		requestRead.Close()
		responseWrite.Close()
		return Result{}, fmt.Errorf("start private ptrace worker: %w", err)
	}
	forwardedSignals := make(chan os.Signal, 2)
	workerDone := make(chan struct{})
	signal.Notify(forwardedSignals, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	defer signal.Stop(forwardedSignals)
	go func() {
		select {
		case received := <-forwardedSignals:
			_ = command.Process.Signal(received)
		case <-ctx.Done():
			_ = command.Process.Signal(unix.SIGTERM)
		case <-workerDone:
		}
	}()
	requestRead.Close()
	responseWrite.Close()
	if err := writeFrame(requestWrite, requestFromOptions(options)); err != nil {
		requestWrite.Close()
		_ = command.Process.Signal(unix.SIGTERM)
		_ = command.Wait()
		close(workerDone)
		return Result{}, err
	}
	requestWrite.Close()
	outcomes := make(chan workerOutcome, 1)
	go func() {
		var response workerResponse
		readErr := readFrame(responseRead, &response)
		outcomes <- workerOutcome{response: response, err: readErr}
	}()
	outcome, relayErr := relayPTY(ctx, master, input, output, terminalFD, outcomes)
	if relayErr != nil {
		_ = command.Process.Signal(unix.SIGTERM)
	}
	waitErr := command.Wait()
	close(workerDone)
	if relayErr != nil {
		outcome = <-outcomes
		if outcome.err != nil {
			return Result{}, fmt.Errorf("interactive PTY relay failed: %v; worker response failed: %w", relayErr, outcome.err)
		}
		return outcome.response.Result, relayErr
	}
	if outcome.err != nil {
		return Result{}, outcome.err
	}
	if waitErr != nil {
		return outcome.response.Result, fmt.Errorf("private ptrace worker exited unsuccessfully: %w", waitErr)
	}
	if outcome.response.Error != "" {
		return outcome.response.Result, errors.New(outcome.response.Error)
	}
	return outcome.response.Result, nil
}

func runWorker(requestReader io.Reader, responseWriter io.Writer) error {
	var request workerRequest
	if err := readFrame(requestReader, &request); err != nil {
		return err
	}
	options, err := request.options()
	if err != nil {
		return err
	}
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	defer stopSignals()
	if err := signalContext.Err(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	target, targetFD, err := revalidateCandidate(options.Target)
	if err != nil {
		return writeFrame(responseWriter, workerResponse{Error: err.Error()})
	}
	if err := validateTargetPTY(target, options.Terminal); err != nil {
		unix.Close(targetFD)
		return writeFrame(responseWriter, workerResponse{Error: err.Error()})
	}
	revalidated, revalidatedFD, err := revalidateCandidate(target)
	if err != nil {
		unix.Close(targetFD)
		return writeFrame(responseWriter, workerResponse{Error: err.Error()})
	}
	unix.Close(targetFD)
	target, targetFD = revalidated, revalidatedFD
	if err := validateTargetPTY(target, options.Terminal); err != nil {
		unix.Close(targetFD)
		return writeFrame(responseWriter, workerResponse{Error: err.Error()})
	}
	result, runErr := runEngine(signalContext, options, target, targetFD)
	response := workerResponse{Result: result}
	if runErr != nil {
		response.Error = runErr.Error()
	}
	return writeFrame(responseWriter, response)
}
