//go:build linux

package hostroot

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

const (
	procSelfMountInfo = "/proc/self/mountinfo"
	procSelfStatus    = "/proc/self/status"
)

type directory interface {
	Fd() uintptr
	Close() error
}

type childProcess interface {
	wait() (int, error)
}

type platform interface {
	effectiveUID() int
	readFile(string) ([]byte, error)
	pathIdentity(string) (escapeutil.FileIdentity, error)
	openDirectoryNoFollow(string) (directory, escapeutil.FileIdentity, error)
	shellExecutable(directory) error
	lockOSThread()
	unshare(int) error
	fchdir(directory) error
	chroot(string) error
	chdir(string) error
	startProcess(string, []string, *os.ProcAttr) (childProcess, error)
}

type workerLauncher interface {
	run(string, []string, io.Reader, io.Writer, io.Writer) error
}

type realPlatform struct{}

func (realPlatform) effectiveUID() int { return os.Geteuid() }
func (realPlatform) readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (realPlatform) pathIdentity(path string) (escapeutil.FileIdentity, error) {
	return escapeutil.PathIdentity(path)
}
func (realPlatform) openDirectoryNoFollow(path string) (directory, escapeutil.FileIdentity, error) {
	return escapeutil.OpenDirectoryNoFollow(path)
}
func (realPlatform) shellExecutable(root directory) error {
	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(int(root.Fd()), "bin/sh", how)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a regular file")
	}
	if stat.Mode&0111 == 0 {
		return fmt.Errorf("execute permission is not set")
	}
	return nil
}
func (realPlatform) lockOSThread()           { runtime.LockOSThread() }
func (realPlatform) unshare(flags int) error { return unix.Unshare(flags) }
func (realPlatform) fchdir(root directory) error {
	return unix.Fchdir(int(root.Fd()))
}
func (realPlatform) chroot(path string) error { return unix.Chroot(path) }
func (realPlatform) chdir(path string) error  { return unix.Chdir(path) }
func (realPlatform) startProcess(name string, argv []string, attr *os.ProcAttr) (childProcess, error) {
	process, err := os.StartProcess(name, argv, attr)
	if err != nil {
		return nil, err
	}
	return osChildProcess{process: process}, nil
}

type osChildProcess struct{ process *os.Process }

func (process osChildProcess) wait() (int, error) {
	state, err := process.process.Wait()
	if err != nil {
		return 0, err
	}
	if exitCode := state.ExitCode(); exitCode >= 0 {
		return exitCode, nil
	}
	return 0, fmt.Errorf("host-root shell terminated without an exit status")
}

type execWorkerLauncher struct{}

func (execWorkerLauncher) run(path string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	/* #nosec G204 -- Peirates intentionally re-executes its own binary in a private worker mode. */
	command := exec.Command(path, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

type preparedWorker struct {
	root     directory
	identity escapeutil.FileIdentity
}

func (prepared *preparedWorker) close() {
	if prepared.root != nil {
		_ = prepared.root.Close()
		prepared.root = nil
	}
}

// Launch auto-selects a mounted host root only when exactly one qualifying
// target is visible, then runs the chroot operation in an isolated worker.
func Launch(stdin io.Reader, stdout, stderr io.Writer) error {
	return launchWith(realPlatform{}, execWorkerLauncher{}, "", stdin, stdout, stderr)
}

// LaunchAt enters the explicitly selected mounted host root in an isolated
// worker. target must be an absolute, unambiguous path.
func LaunchAt(target string, stdin io.Reader, stdout, stderr io.Writer) error {
	return launchWith(realPlatform{}, execWorkerLauncher{}, target, stdin, stdout, stderr)
}

func launchWith(system platform, launcher workerLauncher, target string, stdin io.Reader, stdout, stderr io.Writer) error {
	if target == "" {
		var err error
		target, err = selectAutomaticTarget(system)
		if err != nil {
			return err
		}
	}
	prepared, err := prepareWorker(system, target)
	if err != nil {
		return err
	}
	identity := prepared.identity
	prepared.close()

	fmt.Fprintf(stdout, "Entering mounted host root %s; exit returns to Peirates.\n", target)
	workerArgs := []string{
		WorkerArgument,
		target,
		strconv.FormatUint(identity.Device, 10),
		strconv.FormatUint(identity.Inode, 10),
	}
	if err := launcher.run("/proc/self/exe", workerArgs, stdin, stdout, stderr); err != nil {
		return fmt.Errorf("isolated worker failed: %w", err)
	}
	return nil
}

func selectAutomaticTarget(system platform) (string, error) {
	mountInfo, err := system.readFile(procSelfMountInfo)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", procSelfMountInfo, err)
	}
	mounts, err := escapeutil.ParseMountInfo(mountInfo)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", procSelfMountInfo, err)
	}
	candidates := escapeutil.HostRootCandidates(mounts)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no mounted host-root candidate was found; specify an absolute target path")
	}
	var qualified []string
	var firstQualificationError error
	for _, candidate := range candidates {
		prepared, prepareErr := prepareWorker(system, candidate)
		if prepareErr != nil {
			if firstQualificationError == nil {
				firstQualificationError = fmt.Errorf("mounted host-root candidate %s failed qualification: %w", candidate, prepareErr)
			}
			continue
		}
		prepared.close()
		qualified = append(qualified, candidate)
	}
	qualified = escapeutil.OutermostPaths(qualified)
	sort.Strings(qualified)
	switch len(qualified) {
	case 0:
		if len(candidates) == 1 {
			return "", firstQualificationError
		}
		return "", fmt.Errorf("no mounted host-root candidate passed qualification; specify an absolute target path")
	case 1:
		return qualified[0], nil
	default:
		return "", fmt.Errorf("multiple mounted host-root candidates were found (%s); specify one absolute target path", strings.Join(qualified, ", "))
	}
}

// RunWorker performs the filesystem-root transition in the isolated helper
// process and returns the exit status that the top-level process should use.
func RunWorker(args []string, stdin, stdout, stderr *os.File) int {
	if len(args) != 3 {
		fmt.Fprintf(stderr, "%s internal worker requires a target path, device, and inode\n", outputPrefix)
		return 2
	}
	expectedIdentity, err := parseWorkerIdentity(args[1], args[2])
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", outputPrefix, err)
		return 2
	}
	exitCode, err := runWorkerWith(realPlatform{}, args[0], expectedIdentity, stdin, stdout, stderr, os.Getenv("TERM"))
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", outputPrefix, err)
		return 1
	}
	return exitCode
}

func runWorkerWith(system platform, target string, expectedIdentity escapeutil.FileIdentity, stdin, stdout, stderr *os.File, term string) (int, error) {
	prepared, err := prepareWorker(system, target)
	if err != nil {
		return 0, err
	}
	defer prepared.close()
	if !prepared.identity.Equal(expectedIdentity) {
		return 0, fmt.Errorf("target %s changed after parent preflight", target)
	}

	system.lockOSThread()
	if err := system.unshare(unix.CLONE_FS); err != nil {
		return 0, fmt.Errorf("unshare filesystem attributes: %w", err)
	}
	if err := system.fchdir(prepared.root); err != nil {
		return 0, fmt.Errorf("change directory to mounted host root: %w", err)
	}
	if err := system.chroot("."); err != nil {
		return 0, fmt.Errorf("chroot to mounted host root: %w", err)
	}
	if err := system.chdir("/"); err != nil {
		return 0, fmt.Errorf("change directory to host root: %w", err)
	}

	process, err := system.startProcess("/bin/sh", []string{"sh", "-i"}, &os.ProcAttr{
		Dir:   "/",
		Env:   shellEnvironment(term),
		Files: []*os.File{stdin, stdout, stderr},
	})
	if err != nil {
		return 0, fmt.Errorf("start host-root /bin/sh: %w", err)
	}
	exitCode, err := process.wait()
	if err != nil {
		return 0, fmt.Errorf("wait for host-root /bin/sh: %w", err)
	}
	return exitCode, nil
}

func prepareWorker(system platform, target string) (*preparedWorker, error) {
	if system.effectiveUID() != 0 {
		return nil, fmt.Errorf("effective UID 0 is required")
	}
	status, err := system.readFile(procSelfStatus)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procSelfStatus, err)
	}
	capabilities, err := escapeutil.ParseEffectiveCapabilities(status)
	if err != nil {
		return nil, err
	}
	if !escapeutil.HasCapability(capabilities, unix.CAP_SYS_CHROOT) {
		return nil, fmt.Errorf("required effective capability is missing: CAP_SYS_CHROOT")
	}
	if err := validateTargetPath(target); err != nil {
		return nil, err
	}

	currentRoot, err := system.pathIdentity("/")
	if err != nil {
		return nil, fmt.Errorf("inspect current filesystem root: %w", err)
	}
	root, targetRoot, err := system.openDirectoryNoFollow(target)
	if err != nil {
		return nil, fmt.Errorf("open mounted host root %s without following symlinks: %w", target, err)
	}
	prepared := &preparedWorker{root: root, identity: targetRoot}
	if currentRoot.Equal(targetRoot) {
		prepared.close()
		return nil, fmt.Errorf("target %s matches the current filesystem root", target)
	}
	if err := system.shellExecutable(root); err != nil {
		prepared.close()
		return nil, fmt.Errorf("target shell %s/bin/sh is not executable: %w", target, err)
	}
	return prepared, nil
}

func parseWorkerIdentity(device, inode string) (escapeutil.FileIdentity, error) {
	parsedDevice, err := strconv.ParseUint(device, 10, 64)
	if err != nil {
		return escapeutil.FileIdentity{}, fmt.Errorf("invalid parent-preflight device identity: %w", err)
	}
	parsedInode, err := strconv.ParseUint(inode, 10, 64)
	if err != nil {
		return escapeutil.FileIdentity{}, fmt.Errorf("invalid parent-preflight inode identity: %w", err)
	}
	return escapeutil.FileIdentity{Device: parsedDevice, Inode: parsedInode}, nil
}

func validateTargetPath(target string) error {
	if target == "" {
		return fmt.Errorf("target path is required")
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("target path %q must be absolute", target)
	}
	cleaned := filepath.Clean(target)
	if cleaned == "/" {
		return fmt.Errorf("target path must not be the current root")
	}
	if cleaned != target {
		return fmt.Errorf("target path %q is not normalized; use %q", target, cleaned)
	}
	return nil
}
