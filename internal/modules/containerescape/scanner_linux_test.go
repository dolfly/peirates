//go:build linux

package containerescape

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

type fakeScannerSystem struct {
	uid           int
	environment   map[string]string
	files         map[string][]byte
	identities    map[string]escapeutil.FileIdentity
	kinds         map[string]pathKind
	accessible    map[string]bool
	dockerResults map[string]dockerProbeResult
	dockerErrors  map[string]error
	readPaths     []string
	accessPaths   []string
	dockerPaths   []string
}

func newFakeScannerSystem() *fakeScannerSystem {
	capabilities := uint64(1)<<uint(unix.CAP_SYS_ADMIN) | uint64(1)<<uint(unix.CAP_SYS_CHROOT)
	system := &fakeScannerSystem{
		environment: map[string]string{},
		files: map[string][]byte{
			procSelfStatus: []byte(fmt.Sprintf("Name:\tpeirates\nUid:\t0\t0\t0\t0\nCapEff:\t%016x\n", capabilities)),
			procSelfMountInfo: []byte(
				"1 0 0:1 / / rw - overlay overlay rw,upperdir=/host/upper\n" +
					"2 1 8:1 / /hostroot rw - ext4 /dev/sda1 rw\n" +
					"3 1 0:3 / /proc rw - proc proc rw\n" +
					"4 1 0:4 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"),
			procSelfCgroup: []byte("2:memory:/workload\n"),
		},
		identities:    make(map[string]escapeutil.FileIdentity),
		kinds:         map[string]pathKind{"/var/run/docker.sock": pathSocket},
		accessible:    make(map[string]bool),
		dockerResults: map[string]dockerProbeResult{"/var/run/docker.sock": {Version: "test", APIVersion: "1.44", OS: "linux"}},
		dockerErrors:  make(map[string]error),
	}
	for index, namespace := range []string{"pid", "mnt", "user", "net", "ipc", "uts", "cgroup"} {
		identity := escapeutil.FileIdentity{Device: 1, Inode: uint64(index + 10)}
		system.identities["/proc/self/ns/"+namespace] = identity
		system.identities["/proc/1/ns/"+namespace] = identity
	}
	system.identities["/"] = escapeutil.FileIdentity{Device: 1, Inode: 1}
	system.identities["/proc/1/root"] = escapeutil.FileIdentity{Device: 2, Inode: 1}
	system.identities["/hostroot"] = escapeutil.FileIdentity{Device: 3, Inode: 1}
	system.kinds["/hostroot"] = pathDirectory
	for _, path := range []string{
		"/proc/1/root/bin/sh",
		"/hostroot/bin/sh",
		"/sys/fs/cgroup/memory/release_agent",
		"/sys/fs/cgroup/memory/workload/notify_on_release",
		"/proc/sys/kernel/core_pattern",
	} {
		system.accessible[path] = true
	}
	return system
}

func (system *fakeScannerSystem) effectiveUID() int { return system.uid }
func (system *fakeScannerSystem) getenv(name string) string {
	return system.environment[name]
}
func (system *fakeScannerSystem) readFile(path string) ([]byte, error) {
	system.readPaths = append(system.readPaths, path)
	data, ok := system.files[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), data...), nil
}
func (system *fakeScannerSystem) identity(path string) (escapeutil.FileIdentity, error) {
	identity, ok := system.identities[path]
	if !ok {
		return escapeutil.FileIdentity{}, errors.New("not found")
	}
	return identity, nil
}
func (system *fakeScannerSystem) pathKind(path string) (pathKind, error) {
	kind, ok := system.kinds[path]
	if !ok {
		return pathOther, errors.New("not found")
	}
	return kind, nil
}
func (system *fakeScannerSystem) access(path string, _ uint32) error {
	system.accessPaths = append(system.accessPaths, path)
	if system.accessible[path] {
		return nil
	}
	return errors.New("permission denied")
}
func (system *fakeScannerSystem) dockerProbe(_ context.Context, path string, _ Options) (dockerProbeResult, error) {
	system.dockerPaths = append(system.dockerPaths, path)
	if err := system.dockerErrors[path]; err != nil {
		return dockerProbeResult{}, err
	}
	result, ok := system.dockerResults[path]
	if !ok {
		return dockerProbeResult{}, errors.New("not found")
	}
	return result, nil
}

func TestScanWithSystemFindsObservableCandidates(t *testing.T) {
	system := newFakeScannerSystem()
	findings, err := scanWithSystem(context.Background(), normalizeOptions(Options{}), system)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]escapeutil.Status{
		TechniqueHostPID:       escapeutil.StatusAvailable,
		TechniqueHostRoot:      escapeutil.StatusAvailable,
		TechniqueDockerSocket:  escapeutil.StatusCandidate,
		TechniqueCgroupRelease: escapeutil.StatusCandidate,
		TechniqueCorePattern:   escapeutil.StatusCandidate,
	}
	if len(findings) != len(want) {
		t.Fatalf("finding count = %d, want %d: %#v", len(findings), len(want), findings)
	}
	for _, finding := range findings {
		if err := escapeutil.ValidateFinding(finding); err != nil {
			t.Fatal(err)
		}
		if finding.Status != want[finding.Technique] {
			t.Errorf("%s status = %s, want %s; summary: %s", finding.Technique, finding.Status, want[finding.Technique], finding.Summary)
		}
	}
	if got := strings.Join(system.readPaths, ","); got != "/proc/self/status,/proc/self/mountinfo,/proc/self/cgroup" {
		t.Fatalf("read paths = %q", got)
	}
	if len(system.dockerPaths) != 1 || system.dockerPaths[0] != "/var/run/docker.sock" {
		t.Fatalf("Docker probe paths = %#v", system.dockerPaths)
	}
}

func TestScanWithSystemFailsClosed(t *testing.T) {
	system := newFakeScannerSystem()
	system.uid = 1000
	system.files[procSelfStatus] = []byte("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n")
	system.files[procSelfMountInfo] = []byte("1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
	system.files[procSelfCgroup] = []byte("0::/workload\n")
	delete(system.kinds, "/var/run/docker.sock")
	delete(system.accessible, "/proc/1/root/bin/sh")
	system.identities["/proc/1/root"] = system.identities["/"]

	findings, err := scanWithSystem(context.Background(), normalizeOptions(Options{}), system)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]escapeutil.Status{
		TechniqueHostPID:       escapeutil.StatusBlocked,
		TechniqueHostRoot:      escapeutil.StatusBlocked,
		TechniqueDockerSocket:  escapeutil.StatusBlocked,
		TechniqueCgroupRelease: escapeutil.StatusUnsupported,
		TechniqueCorePattern:   escapeutil.StatusBlocked,
	}
	for _, finding := range findings {
		if finding.Status != want[finding.Technique] {
			t.Errorf("%s status = %s, want %s; summary: %s", finding.Technique, finding.Status, want[finding.Technique], finding.Summary)
		}
	}
}

func TestDockerProbeRejectsSymlinkAndNonSocket(t *testing.T) {
	system := newFakeScannerSystem()
	system.environment["DOCKER_HOST"] = "unix:///symlink.sock"
	system.kinds["/symlink.sock"] = pathSymlink
	system.kinds["/run/docker.sock"] = pathOther
	delete(system.kinds, "/var/run/docker.sock")
	finding := probeDocker(context.Background(), system, normalizeOptions(Options{}))
	if finding.Status != escapeutil.StatusBlocked {
		t.Fatalf("status = %s, want blocked", finding.Status)
	}
	if len(system.dockerPaths) != 0 {
		t.Fatalf("probe followed unsafe paths: %#v", system.dockerPaths)
	}
	joined := strings.Join(finding.Evidence, "\n")
	if !strings.Contains(joined, "rejected symlink") || !strings.Contains(joined, "rejected non-socket") {
		t.Fatalf("missing rejection evidence:\n%s", joined)
	}
}

func TestHostRootAmbiguityIsCandidate(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = append(system.files[procSelfMountInfo], []byte("5 1 8:2 / /second rw - ext4 /dev/sdb1 rw\n")...)
	system.identities["/second"] = escapeutil.FileIdentity{Device: 4, Inode: 1}
	system.kinds["/second"] = pathDirectory
	system.accessible["/second/bin/sh"] = true
	facts := collectFacts(system)
	finding := probeHostRoot(system, facts)
	if finding.Status != escapeutil.StatusCandidate || !strings.Contains(finding.Summary, "explicit operator selection") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestHostRootIgnoresQualifiedNestedMounts(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = append(system.files[procSelfMountInfo], []byte(
		"5 2 0:5 / /hostroot/run/container/rootfs rw - overlay overlay rw\n")...)
	system.identities["/hostroot/run/container/rootfs"] = escapeutil.FileIdentity{Device: 5, Inode: 1}
	system.kinds["/hostroot/run/container/rootfs"] = pathDirectory
	system.accessible["/hostroot/run/container/rootfs/bin/sh"] = true

	finding := probeHostRoot(system, collectFacts(system))
	if finding.Status != escapeutil.StatusAvailable ||
		!strings.Contains(finding.Summary, "one distinct mounted host root") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestCgroupReleaseRequiresWritableControlsInSameHierarchy(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = []byte(
		"1 0 0:1 / / rw - overlay overlay rw,upperdir=/host/upper\n" +
			"4 1 0:4 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
			"5 1 0:5 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n")
	system.files[procSelfCgroup] = []byte("2:memory:/workload\n3:cpu:/workload\n")
	system.accessible = map[string]bool{
		"/sys/fs/cgroup/memory/release_agent":           true,
		"/sys/fs/cgroup/cpu/workload/notify_on_release": true,
	}

	finding := probeCgroupRelease(system, collectFacts(system))
	if finding.Status != escapeutil.StatusBlocked ||
		!strings.Contains(finding.Summary, "no single cgroup v1 hierarchy") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestScanHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, err := scanWithSystem(ctx, normalizeOptions(Options{}), newFakeScannerSystem())
	if !errors.Is(err, context.Canceled) || findings != nil {
		t.Fatalf("scanWithSystem() = %#v, %v; want context.Canceled", findings, err)
	}
}
