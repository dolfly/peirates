//go:build linux && amd64

package hostpidptrace

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

const maxBufferedShellInput = 1024 * 1024

type workerOutcome struct {
	response workerResponse
	err      error
}

func launchInteractive(ctx context.Context, target Candidate, input io.Reader, output io.Writer, terminalFD int) (Result, error) {
	master, terminal, err := openTargetPTY(target)
	if err != nil {
		return Result{}, err
	}
	defer master.Close()
	options, err := normalizeRunOptions(RunOptions{Target: target, Terminal: terminal})
	if err != nil {
		return Result{}, err
	}
	return launchWorker(ctx, options, input, output, terminalFD, master)
}

func openTargetPTY(target Candidate) (*os.File, terminalSpec, error) {
	rootFD, err := unix.Open(fmt.Sprintf("/proc/%d/root", target.PID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, terminalSpec{}, fmt.Errorf("open target root for PTY: %w", err)
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return nil, terminalSpec{}, fmt.Errorf("inspect target root for PTY: %w", err)
	}
	if (Identity{Device: uint64(rootStat.Dev), Inode: rootStat.Ino}) != target.RootID {
		return nil, terminalSpec{}, errors.New("target root identity changed before PTY creation")
	}
	masterFD, err := unix.Openat(rootFD, "dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, terminalSpec{}, fmt.Errorf("open target /dev/ptmx: %w", err)
	}
	closeMaster := true
	defer func() {
		if closeMaster {
			_ = unix.Close(masterFD)
		}
	}()
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		return nil, terminalSpec{}, fmt.Errorf("unlock target PTY: %w", err)
	}
	number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil || number < 0 || number > 1_000_000 {
		return nil, terminalSpec{}, errors.New("read target PTY number")
	}
	spec, err := inspectTargetPTY(rootFD, number)
	if err != nil {
		return nil, terminalSpec{}, err
	}
	if err := unix.SetNonblock(masterFD, true); err != nil {
		return nil, terminalSpec{}, fmt.Errorf("set target PTY nonblocking: %w", err)
	}
	closeMaster = false
	return os.NewFile(uintptr(masterFD), "hostpid-ptrace-master"), spec, nil
}

func inspectTargetPTY(rootFD, number int) (terminalSpec, error) {
	var stat unix.Stat_t
	path := fmt.Sprintf("dev/pts/%d", number)
	if err := unix.Fstatat(rootFD, path, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return terminalSpec{}, fmt.Errorf("inspect target PTY slave: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return terminalSpec{}, errors.New("target PTY slave is not a character device")
	}
	return terminalSpec{
		Number: number, Identity: Identity{Device: uint64(stat.Dev), Inode: stat.Ino},
		DeviceID: uint64(stat.Rdev),
	}, nil
}

func validateTargetPTY(target Candidate, terminal terminalSpec) error {
	rootFD, err := unix.Open(fmt.Sprintf("/proc/%d/root", target.PID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("reopen target root for PTY validation: %w", err)
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return fmt.Errorf("inspect reopened target root: %w", err)
	}
	if (Identity{Device: uint64(rootStat.Dev), Inode: rootStat.Ino}) != target.RootID {
		return errors.New("target root identity changed before PTY validation")
	}
	actual, err := inspectTargetPTY(rootFD, terminal.Number)
	if err != nil {
		return err
	}
	if actual != terminal {
		return errors.New("target PTY slave identity changed before attach")
	}
	return nil
}

func relayPTY(ctx context.Context, master *os.File, input io.Reader, output io.Writer, terminalFD int, outcomes <-chan workerOutcome) (workerOutcome, error) {
	masterFD := int(master.Fd())
	var pending []byte
	if terminalFD >= 0 {
		if reader, ok := input.(*bufio.Reader); ok && reader.Buffered() > 0 {
			pending = make([]byte, reader.Buffered())
			if _, err := io.ReadFull(reader, pending); err != nil {
				return workerOutcome{}, fmt.Errorf("read buffered terminal input: %w", err)
			}
		}
		_ = copyTerminalSize(terminalFD, masterFD)
	} else {
		data, err := io.ReadAll(io.LimitReader(input, maxBufferedShellInput+1))
		if err != nil {
			return workerOutcome{}, fmt.Errorf("read scripted shell input: %w", err)
		}
		if len(data) > maxBufferedShellInput {
			return workerOutcome{}, fmt.Errorf("scripted shell input exceeds %d bytes", maxBufferedShellInput)
		}
		pending = append(data, byte(4))
	}

	resize := make(chan os.Signal, 1)
	if terminalFD >= 0 {
		signal.Notify(resize, unix.SIGWINCH)
		defer signal.Stop(resize)
	}
	inputOpen := terminalFD >= 0
	for {
		select {
		case outcome := <-outcomes:
			if err := drainPTY(masterFD, output); err != nil {
				return outcome, err
			}
			return outcome, nil
		case <-ctx.Done():
			return workerOutcome{}, ctx.Err()
		case <-resize:
			_ = copyTerminalSize(terminalFD, masterFD)
		default:
		}

		masterEvents := int16(unix.POLLIN | unix.POLLERR | unix.POLLHUP)
		if len(pending) != 0 {
			masterEvents |= unix.POLLOUT
		}
		pollDescriptors := []unix.PollFd{{Fd: int32(masterFD), Events: masterEvents}}
		if inputOpen {
			pollDescriptors = append(pollDescriptors, unix.PollFd{Fd: int32(terminalFD), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP})
		}
		if _, err := unix.Poll(pollDescriptors, 100); err != nil && !errors.Is(err, unix.EINTR) {
			return workerOutcome{}, fmt.Errorf("poll interactive PTY: %w", err)
		}
		if pollDescriptors[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0 {
			if err := readAvailablePTY(masterFD, output); err != nil {
				return workerOutcome{}, err
			}
		}
		if len(pending) != 0 && pollDescriptors[0].Revents&unix.POLLOUT != 0 {
			var err error
			pending, err = writeAvailablePTY(masterFD, pending)
			if err != nil {
				return workerOutcome{}, err
			}
		}
		if inputOpen && len(pollDescriptors) == 2 && pollDescriptors[1].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0 {
			buffer := make([]byte, 4096)
			count, err := unix.Read(terminalFD, buffer)
			if count > 0 {
				pending = append(pending, buffer[:count]...)
			}
			if count == 0 || errors.Is(err, unix.EIO) {
				pending = append(pending, byte(4))
				inputOpen = false
			} else if err != nil && !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
				return workerOutcome{}, fmt.Errorf("read local terminal: %w", err)
			}
		}
	}
}

func copyTerminalSize(inputFD, masterFD int) error {
	window, err := unix.IoctlGetWinsize(inputFD, unix.TIOCGWINSZ)
	if err != nil {
		return err
	}
	return unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, window)
}

func readAvailablePTY(masterFD int, output io.Writer) error {
	buffer := make([]byte, 32*1024)
	for {
		count, err := unix.Read(masterFD, buffer)
		if count > 0 {
			if _, writeErr := output.Write(buffer[:count]); writeErr != nil {
				return fmt.Errorf("write interactive shell output: %w", writeErr)
			}
		}
		if count == 0 || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EIO) {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read interactive shell output: %w", err)
		}
	}
}

func writeAvailablePTY(masterFD int, pending []byte) ([]byte, error) {
	for len(pending) != 0 {
		count, err := unix.Write(masterFD, pending)
		if count > 0 {
			pending = pending[count:]
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EIO) {
			return pending, nil
		}
		if err != nil {
			return pending, fmt.Errorf("write interactive shell input: %w", err)
		}
	}
	return pending, nil
}

func drainPTY(masterFD int, output io.Writer) error {
	for attempts := 0; attempts < 5; attempts++ {
		poll := []unix.PollFd{{Fd: int32(masterFD), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}
		if _, err := unix.Poll(poll, 50); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if poll[0].Revents == 0 {
			continue
		}
		if err := readAvailablePTY(masterFD, output); err != nil {
			return err
		}
	}
	return nil
}
