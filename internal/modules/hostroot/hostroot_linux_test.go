//go:build linux

package hostroot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

type fakeDirectory struct {
	fd     uintptr
	path   string
	system *fakePlatform
	closed bool
}

func (directory *fakeDirectory) Fd() uintptr { return directory.fd }
func (directory *fakeDirectory) Close() error {
	if directory.closed {
		return os.ErrClosed
	}
	directory.closed = true
	directory.system.calls = append(directory.system.calls, "close:"+directory.path)
	delete(directory.system.openDirectories, directory.path)
	return directory.system.errors["close:"+directory.path]
}

type fakeChild struct {
	exitCode int
	err      error
	calls    *[]string
}

func (child fakeChild) wait() (int, error) {
	*child.calls = append(*child.calls, "wait")
	return child.exitCode, child.err
}

type fakePlatform struct {
	euid            int
	status          []byte
	mountInfo       []byte
	identities      map[string]escapeutil.FileIdentity
	errors          map[string]error
	openDirectories map[string]*fakeDirectory
	nextFD          uintptr
	calls           []string
	exitCode        int
	startName       string
	startArgv       []string
	startAttr       *os.ProcAttr
}

func newFakePlatform() *fakePlatform {
	capabilities := uint64(1) << uint(unix.CAP_SYS_CHROOT)
	return &fakePlatform{
		euid:      0,
		status:    []byte(fmt.Sprintf("Name:\tpeirates\nCapEff:\t%016x\n", capabilities)),
		mountInfo: []byte("10 1 8:1 / /hostroot rw,relatime - ext4 /dev/sda1 rw\n"),
		identities: map[string]escapeutil.FileIdentity{
			"/":         {Device: 1, Inode: 1},
			"/hostroot": {Device: 2, Inode: 1},
			"/node":     {Device: 3, Inode: 1},
		},
		errors:          make(map[string]error),
		openDirectories: make(map[string]*fakeDirectory),
		nextFD:          10,
		exitCode:        7,
	}
}

func (system *fakePlatform) effectiveUID() int { return system.euid }
func (system *fakePlatform) readFile(path string) ([]byte, error) {
	system.calls = append(system.calls, "read:"+path)
	if err := system.errors["read:"+path]; err != nil {
		return nil, err
	}
	if path == procSelfMountInfo {
		return system.mountInfo, nil
	}
	return system.status, nil
}
func (system *fakePlatform) pathIdentity(path string) (escapeutil.FileIdentity, error) {
	system.calls = append(system.calls, "identity:"+path)
	if err := system.errors["identity:"+path]; err != nil {
		return escapeutil.FileIdentity{}, err
	}
	identity, ok := system.identities[path]
	if !ok {
		return escapeutil.FileIdentity{}, fmt.Errorf("missing fake identity for %s", path)
	}
	return identity, nil
}
func (system *fakePlatform) openDirectoryNoFollow(path string) (directory, escapeutil.FileIdentity, error) {
	system.calls = append(system.calls, "open:"+path)
	if err := system.errors["open:"+path]; err != nil {
		return nil, escapeutil.FileIdentity{}, err
	}
	identity, ok := system.identities[path]
	if !ok {
		return nil, escapeutil.FileIdentity{}, fmt.Errorf("missing fake identity for %s", path)
	}
	directory := &fakeDirectory{fd: system.nextFD, path: path, system: system}
	system.nextFD++
	system.openDirectories[path] = directory
	return directory, identity, nil
}
func (system *fakePlatform) shellExecutable(root directory) error {
	path := root.(*fakeDirectory).path
	system.calls = append(system.calls, "shell:"+path)
	return system.errors["shell:"+path]
}
func (system *fakePlatform) lockOSThread() { system.calls = append(system.calls, "lock") }
func (system *fakePlatform) unshare(flags int) error {
	system.calls = append(system.calls, fmt.Sprintf("unshare:%d", flags))
	return system.errors["unshare"]
}
func (system *fakePlatform) fchdir(root directory) error {
	path := root.(*fakeDirectory).path
	system.calls = append(system.calls, "fchdir:"+path)
	return system.errors["fchdir"]
}
func (system *fakePlatform) chroot(path string) error {
	system.calls = append(system.calls, "chroot:"+path)
	return system.errors["chroot"]
}
func (system *fakePlatform) chdir(path string) error {
	system.calls = append(system.calls, "chdir:"+path)
	return system.errors["chdir"]
}
func (system *fakePlatform) startProcess(name string, argv []string, attr *os.ProcAttr) (childProcess, error) {
	system.calls = append(system.calls, "start:"+name)
	system.startName = name
	system.startArgv = append([]string(nil), argv...)
	copyAttr := *attr
	copyAttr.Env = append([]string(nil), attr.Env...)
	copyAttr.Files = append([]*os.File(nil), attr.Files...)
	system.startAttr = &copyAttr
	if err := system.errors["start"]; err != nil {
		return nil, err
	}
	return fakeChild{exitCode: system.exitCode, err: system.errors["wait"], calls: &system.calls}, nil
}

type fakeLauncher struct {
	path   string
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	err    error
}

func (launcher *fakeLauncher) run(path string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	launcher.path = path
	launcher.args = append([]string(nil), args...)
	launcher.stdin = stdin
	launcher.stdout = stdout
	launcher.stderr = stderr
	return launcher.err
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("unexpected input read") }

func TestValidateTargetPath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr string
	}{
		{path: "", wantErr: "required"},
		{path: "hostroot", wantErr: "must be absolute"},
		{path: "/", wantErr: "must not be the current root"},
		{path: "/hostroot/", wantErr: "not normalized"},
		{path: "/hostroot/../node", wantErr: "not normalized"},
		{path: "/hostroot"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			err := validateTargetPath(test.path)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestPrepareWorkerQualificationFailures(t *testing.T) {
	permissionError := errors.New("permission denied")
	tests := []struct {
		name    string
		mutate  func(*fakePlatform)
		wantErr string
	}{
		{name: "not root", mutate: func(system *fakePlatform) { system.euid = 1000 }, wantErr: "effective UID 0"},
		{name: "status unavailable", mutate: func(system *fakePlatform) { system.errors["read:"+procSelfStatus] = permissionError }, wantErr: "read /proc/self/status"},
		{name: "missing capability", mutate: func(system *fakePlatform) { system.status = []byte("CapEff:\t0000000000000000\n") }, wantErr: "CAP_SYS_CHROOT"},
		{name: "root identity unavailable", mutate: func(system *fakePlatform) { system.errors["identity:/"] = permissionError }, wantErr: "inspect current filesystem root"},
		{name: "target open", mutate: func(system *fakePlatform) { system.errors["open:/hostroot"] = permissionError }, wantErr: "without following symlinks"},
		{name: "same root", mutate: func(system *fakePlatform) { system.identities["/hostroot"] = system.identities["/"] }, wantErr: "matches the current filesystem root"},
		{name: "missing shell", mutate: func(system *fakePlatform) { system.errors["shell:/hostroot"] = permissionError }, wantErr: "is not executable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakePlatform()
			test.mutate(system)
			prepared, err := prepareWorker(system, "/hostroot")
			if prepared != nil {
				prepared.close()
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
			if len(system.openDirectories) != 0 {
				t.Fatalf("descriptors leaked: %#v", system.openDirectories)
			}
		})
	}
}

func TestRealPlatformShellQualificationStaysInsideTargetRoot(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(target+"/bin", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+"/bin/dash", []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dash", target+"/bin/sh"); err != nil {
		t.Fatal(err)
	}
	root, _, err := escapeutil.OpenDirectoryNoFollow(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := (realPlatform{}).shellExecutable(root); err != nil {
		t.Fatalf("confined executable symlink was rejected: %v", err)
	}

	if err := os.Remove(target + "/bin/sh"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../bin/sh", target+"/bin/sh"); err != nil {
		t.Fatal(err)
	}
	if err := (realPlatform{}).shellExecutable(root); err == nil {
		t.Fatal("shell symlink escaping the target root was accepted")
	}
}

func TestRealPlatformRejectsNonExecutableShell(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(target+"/bin", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+"/bin/sh", []byte("#!/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	root, _, err := escapeutil.OpenDirectoryNoFollow(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := (realPlatform{}).shellExecutable(root); err == nil || !strings.Contains(err.Error(), "execute permission") {
		t.Fatalf("error = %v, want execute-permission failure", err)
	}
}

func TestLaunchAtUsesPrivateWorkerWithoutReadingInput(t *testing.T) {
	system := newFakePlatform()
	launcher := &fakeLauncher{}
	stdin := panicReader{}
	var stdout, stderr bytes.Buffer
	if err := launchWith(system, launcher, "/hostroot", stdin, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if launcher.path != "/proc/self/exe" || !reflect.DeepEqual(launcher.args, []string{WorkerArgument, "/hostroot", "2", "1"}) {
		t.Fatalf("worker invocation = %q %#v", launcher.path, launcher.args)
	}
	if launcher.stdin != stdin || launcher.stdout != &stdout || launcher.stderr != &stderr {
		t.Fatal("worker did not inherit the supplied streams")
	}
	if !strings.Contains(stdout.String(), "exit returns to Peirates") {
		t.Fatalf("boundary message missing: %q", stdout.String())
	}
	if len(system.openDirectories) != 0 {
		t.Fatalf("preflight descriptor was not closed: %#v", system.openDirectories)
	}
}

func TestLaunchAutoSelectsOnlyCandidate(t *testing.T) {
	system := newFakePlatform()
	launcher := &fakeLauncher{}
	if err := launchWith(system, launcher, "", strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(launcher.args, []string{WorkerArgument, "/hostroot", "2", "1"}) {
		t.Fatalf("worker arguments = %#v", launcher.args)
	}
	if countCall(system.calls, "open:/hostroot") != 2 {
		t.Fatalf("auto-selection did not re-run target preflight: %v", system.calls)
	}
	if len(system.openDirectories) != 0 {
		t.Fatalf("preflight descriptor was not closed: %#v", system.openDirectories)
	}
}

func TestLaunchReportsWorkerFailure(t *testing.T) {
	system := newFakePlatform()
	launcher := &fakeLauncher{err: errors.New("exit status 7")}
	err := launchWith(system, launcher, "/hostroot", strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "isolated worker failed: exit status 7") {
		t.Fatalf("error = %v", err)
	}
}

func TestAutomaticTargetSelection(t *testing.T) {
	tests := []struct {
		name      string
		mountInfo string
		mutate    func(*fakePlatform)
		want      string
		wantErr   string
	}{
		{
			name:      "one qualifying candidate",
			mountInfo: "10 1 8:1 / /hostroot rw,relatime - ext4 /dev/sda1 rw\n",
			want:      "/hostroot",
		},
		{
			name:      "no candidate",
			mountInfo: "10 1 0:1 /container / rw,relatime - overlay overlay rw\n",
			wantErr:   "no mounted host-root candidate",
		},
		{
			name:      "candidate fails qualification",
			mountInfo: "10 1 8:1 / /hostroot rw,relatime - ext4 /dev/sda1 rw\n",
			mutate:    func(system *fakePlatform) { system.errors["shell:/hostroot"] = errors.New("missing") },
			wantErr:   "failed qualification",
		},
		{
			name: "ambiguous",
			mountInfo: "10 1 8:1 / /hostroot rw,relatime - ext4 /dev/sda1 rw\n" +
				"11 1 8:1 / /node rw,relatime - ext4 /dev/sda1 rw\n",
			wantErr: "multiple mounted host-root candidates",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakePlatform()
			system.mountInfo = []byte(test.mountInfo)
			if test.mutate != nil {
				test.mutate(system)
			}
			got, err := selectAutomaticTarget(system)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("selectAutomaticTarget() = %q, %v; want %q, nil", got, err, test.want)
			}
			if len(system.openDirectories) != 0 {
				t.Fatalf("descriptors leaked: %#v", system.openDirectories)
			}
		})
	}
}

func TestAutomaticTargetSelectionIgnoresQualifiedNestedRoots(t *testing.T) {
	system := newFakePlatform()
	system.mountInfo = []byte(
		"10 1 8:1 / /hostroot rw,relatime - ext4 /dev/sda1 rw\n" +
			"11 10 0:2 / /hostroot/run/container/rootfs rw - overlay overlay rw\n")
	system.identities["/hostroot/run/container/rootfs"] = escapeutil.FileIdentity{Device: 4, Inode: 1}

	got, err := selectAutomaticTarget(system)
	if err != nil || got != "/hostroot" {
		t.Fatalf("selectAutomaticTarget() = %q, %v", got, err)
	}
	if len(system.openDirectories) != 0 {
		t.Fatalf("descriptors leaked: %#v", system.openDirectories)
	}
}

func TestAutomaticTargetReadAndParseFailures(t *testing.T) {
	system := newFakePlatform()
	system.errors["read:"+procSelfMountInfo] = errors.New("denied")
	if _, err := selectAutomaticTarget(system); err == nil || !strings.Contains(err.Error(), "read /proc/self/mountinfo") {
		t.Fatalf("read error = %v", err)
	}

	system = newFakePlatform()
	system.mountInfo = []byte("malformed\n")
	if _, err := selectAutomaticTarget(system); err == nil || !strings.Contains(err.Error(), "parse /proc/self/mountinfo") {
		t.Fatalf("parse error = %v", err)
	}
}

func TestWorkerTransitionOrderAndShellContract(t *testing.T) {
	system := newFakePlatform()
	exitCode, err := runWorkerWith(system, "/hostroot", system.identities["/hostroot"], os.Stdin, os.Stdout, os.Stderr, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 7 {
		t.Fatalf("exit code = %d, want 7", exitCode)
	}
	wantSequence := []string{
		"read:/proc/self/status",
		"identity:/",
		"open:/hostroot",
		"shell:/hostroot",
		"lock",
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		"fchdir:/hostroot",
		"chroot:.",
		"chdir:/",
		"start:/bin/sh",
		"wait",
		"close:/hostroot",
	}
	assertOrderedCalls(t, system.calls, wantSequence)
	if system.startName != "/bin/sh" || !reflect.DeepEqual(system.startArgv, []string{"sh", "-i"}) {
		t.Fatalf("shell = %q %#v", system.startName, system.startArgv)
	}
	wantEnvironment := []string{
		"HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PS1=[peirates-hostroot]# ", "TERM=xterm-256color",
	}
	if !reflect.DeepEqual(system.startAttr.Env, wantEnvironment) {
		t.Fatalf("environment = %#v, want %#v", system.startAttr.Env, wantEnvironment)
	}
	if system.startAttr.Dir != "/" || !reflect.DeepEqual(system.startAttr.Files, []*os.File{os.Stdin, os.Stdout, os.Stderr}) {
		t.Fatalf("process attributes = %#v", system.startAttr)
	}
	for _, forbidden := range []string{"LD_PRELOAD", "BASH_ENV", "KUBERNETES_SERVICE_HOST"} {
		if strings.Contains(strings.Join(system.startAttr.Env, "\n"), forbidden) {
			t.Fatalf("environment inherited forbidden variable %s", forbidden)
		}
	}
}

func TestWorkerStopsAfterEveryMutationFailure(t *testing.T) {
	tests := []struct {
		name    string
		failKey string
		wantErr string
	}{
		{name: "unshare", failKey: "unshare", wantErr: "unshare filesystem attributes"},
		{name: "fchdir", failKey: "fchdir", wantErr: "change directory to mounted host root"},
		{name: "chroot", failKey: "chroot", wantErr: "chroot to mounted host root"},
		{name: "chdir", failKey: "chdir", wantErr: "change directory to host root"},
		{name: "start", failKey: "start", wantErr: "start host-root /bin/sh"},
		{name: "wait", failKey: "wait", wantErr: "wait for host-root /bin/sh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakePlatform()
			system.errors[test.failKey] = errors.New("injected failure")
			_, err := runWorkerWith(system, "/hostroot", system.identities["/hostroot"], os.Stdin, os.Stdout, os.Stderr, "")
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
			if test.failKey != "wait" && test.failKey != "start" && containsCall(system.calls, "start:/bin/sh") {
				t.Fatalf("shell started after %s failure: %v", test.name, system.calls)
			}
			if test.failKey == "start" && containsCall(system.calls, "wait") {
				t.Fatalf("worker waited after start failure: %v", system.calls)
			}
			if len(system.openDirectories) != 0 {
				t.Fatalf("descriptor leaked after %s failure: %#v", test.name, system.openDirectories)
			}
		})
	}
}

func TestRunWorkerRejectsArgumentsBeforePreflight(t *testing.T) {
	for _, args := range [][]string{nil, {"/hostroot"}, {"/hostroot", "2", "1", "unexpected"}} {
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if got := RunWorker(args, os.Stdin, os.Stdout, writeEnd); got != 2 {
			t.Fatalf("RunWorker(%q) exit code = %d, want 2", args, got)
		}
		if err := writeEnd.Close(); err != nil {
			t.Fatal(err)
		}
		output, err := io.ReadAll(readEnd)
		if err != nil {
			t.Fatal(err)
		}
		_ = readEnd.Close()
		if !strings.Contains(string(output), "requires a target path, device, and inode") {
			t.Fatalf("output = %q", output)
		}
	}
}

func TestWorkerRejectsTargetIdentityChangeBeforeMutation(t *testing.T) {
	system := newFakePlatform()
	expected := system.identities["/hostroot"]
	system.identities["/hostroot"] = escapeutil.FileIdentity{Device: 9, Inode: 9}

	_, err := runWorkerWith(system, "/hostroot", expected, os.Stdin, os.Stdout, os.Stderr, "")
	if err == nil || !strings.Contains(err.Error(), "changed after parent preflight") {
		t.Fatalf("error = %v", err)
	}
	for _, mutation := range []string{"lock", "fchdir:/hostroot", "chroot:.", "start:/bin/sh"} {
		if containsCall(system.calls, mutation) {
			t.Fatalf("mutation %q occurred after identity mismatch: %v", mutation, system.calls)
		}
	}
	if len(system.openDirectories) != 0 {
		t.Fatalf("descriptor leaked after identity mismatch: %#v", system.openDirectories)
	}
}

func TestParseWorkerIdentity(t *testing.T) {
	identity, err := parseWorkerIdentity("2", "3")
	if err != nil || identity != (escapeutil.FileIdentity{Device: 2, Inode: 3}) {
		t.Fatalf("parseWorkerIdentity() = %#v, %v", identity, err)
	}
	for _, values := range [][2]string{{"invalid", "3"}, {"2", "invalid"}} {
		if _, err := parseWorkerIdentity(values[0], values[1]); err == nil {
			t.Fatalf("parseWorkerIdentity(%q, %q) unexpectedly succeeded", values[0], values[1])
		}
	}
}

func assertOrderedCalls(t *testing.T, calls, want []string) {
	t.Helper()
	position := 0
	for _, call := range calls {
		if position < len(want) && call == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("calls do not contain ordered sequence\ncalls: %#v\nwant:  %#v", calls, want)
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func countCall(calls []string, want string) int {
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}
