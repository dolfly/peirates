//go:build linux && amd64

package hostpidptrace

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
)

var requiredNamespaces = []string{"pid", "user", "mnt", "uts", "ipc", "net", "cgroup"}

type processStatus struct {
	state       byte
	uids        [4]uint32
	threads     int
	tracerPID   int
	coreDumping int
	pidDepth    int
	seccomp     int
	capEff      uint64
	hasCapEff   bool
}

type boundaryIdentity struct {
	namespaces map[string]Identity
	root       Identity
	hasTime    bool
	pidDepth   int
}

func probePlatform(ctx context.Context) (ProbeResult, error) {
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	if os.Geteuid() != 0 {
		return ProbeResult{}, errors.New("effective UID 0 is required")
	}
	selfStatusData, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ProbeResult{}, fmt.Errorf("read current process status: %w", err)
	}
	selfStatus, err := parseStatus(selfStatusData)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("parse current process status: %w", err)
	}
	if !selfStatus.hasCapEff {
		return ProbeResult{}, errors.New("CapEff is missing from /proc/self/status")
	}
	if err := requirePtraceCapabilities(selfStatus.capEff); err != nil {
		return ProbeResult{}, err
	}
	for _, namespace := range []string{"pid", "user"} {
		current, currentErr := identityPath(filepath.Join("/proc/self/ns", namespace))
		visibleOne, oneErr := identityPath(filepath.Join("/proc/1/ns", namespace))
		if currentErr != nil || oneErr != nil {
			return ProbeResult{}, fmt.Errorf("inspect %s namespace identities", namespace)
		}
		if current != visibleOne {
			return ProbeResult{}, fmt.Errorf("current %s namespace differs from visible PID 1; hostPID and a compatible user namespace are required", namespace)
		}
	}
	selfPidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("pidfd_open is required: %w", err)
	}
	_ = unix.Close(selfPidfd)

	result := ProbeResult{SeccompMode: selfStatus.seccomp}
	if data, readErr := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); readErr == nil {
		value, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if parseErr != nil {
			return ProbeResult{}, fmt.Errorf("parse Yama ptrace_scope: %w", parseErr)
		}
		result.YamaScope = &value
		if value == 3 {
			return ProbeResult{}, errors.New("Yama ptrace_scope 3 permanently prohibits ptrace attach; Peirates will not modify it")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		result.Warnings = append(result.Warnings, "Yama ptrace_scope could not be read; the real attach check remains authoritative")
	}
	for _, path := range []string{"/proc/self/attr/current", "/proc/self/attr/exec"} {
		if data, readErr := os.ReadFile(path); readErr == nil {
			if label := sanitizeDisplay(string(data), 256); label != "" && label != "unconfined" {
				result.SecurityLabel = label
				break
			}
		}
	}
	if result.SeccompMode != 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("current seccomp mode is %d; the real ptrace operation may still be blocked", result.SeccompMode))
	}
	if result.SecurityLabel != "" {
		result.Warnings = append(result.Warnings, "an AppArmor or SELinux process label is active; Peirates will not alter it")
	}

	boundary, err := inspectBoundary(1)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("inspect visible PID 1 boundary: %w", err)
	}
	ancestors := currentAncestors()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ProbeResult{}, fmt.Errorf("enumerate /proc: %w", err)
	}
	var pids []int
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	rejections := make(map[string]int)
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return ProbeResult{}, err
		}
		candidate, reason, inspectErr := inspectCandidate(pid, boundary, ancestors)
		if inspectErr != nil {
			rejections[reason]++
			continue
		}
		result.Candidates = append(result.Candidates, candidate)
	}
	if len(result.Candidates) == 0 {
		var classes []string
		for class, count := range rejections {
			classes = append(classes, fmt.Sprintf("%s=%d", class, count))
		}
		sort.Strings(classes)
		result.Warnings = append(result.Warnings, "no eligible disposable targets were found ("+strings.Join(classes, ", ")+")")
	}
	return result, nil
}

func inspectBoundary(pid int) (boundaryIdentity, error) {
	boundary := boundaryIdentity{namespaces: make(map[string]Identity)}
	for _, namespace := range requiredNamespaces {
		identity, err := identityPath(fmt.Sprintf("/proc/%d/ns/%s", pid, namespace))
		if err != nil {
			return boundary, fmt.Errorf("inspect %s namespace: %w", namespace, err)
		}
		boundary.namespaces[namespace] = identity
	}
	timeID, err := identityPath(fmt.Sprintf("/proc/%d/ns/time", pid))
	if err == nil {
		boundary.namespaces["time"] = timeID
		boundary.hasTime = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return boundary, fmt.Errorf("inspect time namespace: %w", err)
	}
	root, err := identityPath(fmt.Sprintf("/proc/%d/root", pid))
	if err != nil {
		return boundary, fmt.Errorf("inspect filesystem root: %w", err)
	}
	boundary.root = root
	statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return boundary, fmt.Errorf("inspect PID namespace depth: %w", err)
	}
	status, err := parseStatus(statusData)
	if err != nil {
		return boundary, fmt.Errorf("parse PID namespace depth: %w", err)
	}
	boundary.pidDepth = status.pidDepth
	return boundary, nil
}

func inspectCandidate(pid int, boundary boundaryIdentity, ancestors map[int]bool) (Candidate, string, error) {
	reject := func(class, detail string) (Candidate, string, error) {
		return Candidate{}, class, errors.New(detail)
	}
	if class, detail := prohibitedTargetReason(pid, os.Getpid(), ancestors); class != "" {
		return reject(class, detail)
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d", pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return reject("unstable", "process directory could not be opened")
	}
	defer unix.Close(fd)
	base := fmt.Sprintf("/proc/self/fd/%d", fd)
	statData, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return reject("unstable", "process stat could not be read")
	}
	comm, state, parentPID, startTime, err := parseStat(statData)
	if err != nil {
		return reject("metadata", err.Error())
	}
	_ = parentPID
	statusData, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return reject("unstable", "process status could not be read")
	}
	status, err := parseStatus(statusData)
	if err != nil {
		return reject("metadata", err.Error())
	}
	if status.state != state {
		return reject("unstable", "state changed during inspection")
	}
	if status.pidDepth != boundary.pidDepth {
		return reject("namespace-mismatch", "PID namespace depth differs from visible PID 1")
	}
	tasks, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil {
		return reject("unstable", "target task directory could not be read")
	}
	executable, err := os.Readlink(filepath.Join(base, "exe"))
	if class, detail := processMetadataReason(status, len(tasks), executable, err); class != "" {
		return reject(class, detail)
	}
	namespaceIDs := make(map[string]Identity)
	for _, namespace := range requiredNamespaces {
		identity, identityErr := identityPath(filepath.Join(base, "ns", namespace))
		if identityErr != nil || identity != boundary.namespaces[namespace] {
			return reject("namespace-mismatch", namespace+" namespace differs from visible PID 1")
		}
		namespaceIDs[namespace] = identity
	}
	if boundary.hasTime {
		identity, identityErr := identityPath(filepath.Join(base, "ns/time"))
		if identityErr != nil || identity != boundary.namespaces["time"] {
			return reject("namespace-mismatch", "time namespace differs from visible PID 1")
		}
		namespaceIDs["time"] = identity
	}
	root, err := identityPath(filepath.Join(base, "root"))
	if err != nil || root != boundary.root {
		return reject("root-mismatch", "filesystem root differs from visible PID 1")
	}
	if err := unix.Access(filepath.Join(base, "root/bin/sh"), unix.X_OK); err != nil {
		return reject("missing-shell", "target root has no executable /bin/sh")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return reject("pidfd", "target cannot be represented by a pidfd")
	}
	defer unix.Close(pidfd)
	statAgain, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return reject("unstable", "process stat disappeared")
	}
	_, _, _, stableStart, err := parseStat(statAgain)
	if err != nil || stableStart != startTime {
		return reject("unstable", "process identity changed during inspection")
	}
	cmdlineData, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return reject("unstable", "process command line could not be read")
	}
	commandLine := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	commandLineHash := sha256.Sum256(cmdlineData)
	return Candidate{
		PID: pid, StartTime: startTime, Comm: sanitizeDisplay(comm, 64),
		Executable: sanitizeDisplay(executable, 256), CommandLine: sanitizeDisplay(commandLine, 160),
		CommandLineDigest: hex.EncodeToString(commandLineHash[:]),
		State:             status.state, UIDs: status.uids, Threads: status.threads,
		TracerPID: status.tracerPID, CoreDumping: status.coreDumping,
		NamespaceIDs: namespaceIDs, RootID: root, PIDDepth: status.pidDepth,
	}, "", nil
}

func prohibitedTargetReason(pid, self int, ancestors map[int]bool) (string, string) {
	if pid <= 1 {
		return "prohibited-pid", "PID 1 is prohibited"
	}
	if pid == self || ancestors[pid] {
		return "self-or-ancestor", "Peirates and its ancestors are prohibited"
	}
	return "", ""
}

func processMetadataReason(status processStatus, taskCount int, executable string, executableErr error) (string, string) {
	if status.uids != [4]uint32{} {
		return "non-root", "all real/effective/saved/filesystem UIDs must be zero"
	}
	if status.threads != 1 || taskCount != 1 {
		return "multithreaded", "target must have exactly one stable thread"
	}
	if status.tracerPID != 0 {
		return "already-traced", "target is already traced"
	}
	if status.coreDumping != 0 {
		return "core-dumping", "target is dumping core"
	}
	if strings.ContainsRune("DTtXZx", rune(status.state)) {
		return "unsafe-state", "target is stopped, dead, zombie, or uninterruptible"
	}
	if status.pidDepth != 1 {
		return "nested-pid", "target is not at one initial PID namespace level"
	}
	if executableErr != nil || executable == "" {
		return "kernel-thread", "target has no user-space executable"
	}
	return "", ""
}

func requirePtraceCapabilities(capabilities uint64) error {
	var missing []string
	for _, capability := range []struct {
		name string
		bit  int
	}{{"CAP_SYS_PTRACE", unix.CAP_SYS_PTRACE}, {"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN}} {
		if capabilities&(uint64(1)<<uint(capability.bit)) == 0 {
			missing = append(missing, capability.name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("required effective capabilities are missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func revalidateCandidate(expected Candidate) (Candidate, int, error) {
	pidfd, err := unix.PidfdOpen(expected.PID, 0)
	if err != nil {
		return Candidate{}, -1, fmt.Errorf("open target pidfd: %w", err)
	}
	boundary, err := inspectBoundary(1)
	if err != nil {
		unix.Close(pidfd)
		return Candidate{}, -1, err
	}
	actual, _, err := inspectCandidate(expected.PID, boundary, currentAncestors())
	if err != nil {
		unix.Close(pidfd)
		return Candidate{}, -1, fmt.Errorf("target is no longer eligible: %w", err)
	}
	if actual.StartTime != expected.StartTime || actual.RootID != expected.RootID ||
		actual.Comm != expected.Comm || actual.Executable != expected.Executable ||
		actual.CommandLine != expected.CommandLine || actual.CommandLineDigest != expected.CommandLineDigest ||
		!identityMapsEqual(actual.NamespaceIDs, expected.NamespaceIDs) {
		unix.Close(pidfd)
		return Candidate{}, -1, errors.New("target identity changed since confirmation")
	}
	return actual, pidfd, nil
}

func identityMapsEqual(left, right map[string]Identity) bool {
	if len(left) != len(right) {
		return false
	}
	for name, identity := range left {
		if right[name] != identity {
			return false
		}
	}
	return true
}

func identityPath(path string) (Identity, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return Identity{}, err
	}
	return Identity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func parseStatus(data []byte) (processStatus, error) {
	status := processStatus{coreDumping: -1, seccomp: -1}
	var haveState, haveUIDs, haveThreads, haveTracer, havePIDDepth bool
	var err error
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "State:":
			if len(fields) < 2 || len(fields[1]) != 1 {
				return status, errors.New("malformed State")
			}
			status.state, haveState = fields[1][0], true
		case "Uid:":
			if len(fields) != 5 {
				return status, errors.New("malformed Uid")
			}
			for index := range status.uids {
				value, err := strconv.ParseUint(fields[index+1], 10, 32)
				if err != nil {
					return status, errors.New("malformed Uid")
				}
				status.uids[index] = uint32(value)
			}
			haveUIDs = true
		case "Threads:":
			status.threads, err = parseSingleInt(fields)
			if err != nil {
				return status, errors.New("malformed Threads")
			}
			haveThreads = true
		case "TracerPid:":
			status.tracerPID, err = parseSingleInt(fields)
			if err != nil {
				return status, errors.New("malformed TracerPid")
			}
			haveTracer = true
		case "CoreDumping:":
			status.coreDumping, err = parseSingleInt(fields)
			if err != nil {
				return status, errors.New("malformed CoreDumping")
			}
		case "NSpid:", "NStgid:":
			if !havePIDDepth && len(fields) > 1 {
				for _, field := range fields[1:] {
					if _, err := strconv.Atoi(field); err != nil {
						return status, errors.New("malformed PID namespace depth")
					}
				}
				status.pidDepth, havePIDDepth = len(fields)-1, true
			}
		case "Seccomp:":
			status.seccomp, err = parseSingleInt(fields)
			if err != nil {
				return status, errors.New("malformed Seccomp")
			}
		case "CapEff:":
			if len(fields) != 2 {
				return status, errors.New("malformed CapEff")
			}
			value, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return status, errors.New("malformed CapEff")
			}
			status.capEff, status.hasCapEff = value, true
		}
	}
	if err := scanner.Err(); err != nil {
		return status, err
	}
	if !haveState || !haveUIDs || !haveThreads || !haveTracer || !havePIDDepth || status.coreDumping < 0 {
		return status, errors.New("required process status fields are missing")
	}
	return status, nil
}

func parseSingleInt(fields []string) (int, error) {
	if len(fields) != 2 {
		return -1, errors.New("expected one integer")
	}
	value, err := strconv.Atoi(fields[1])
	if err != nil {
		return -1, err
	}
	return value, nil
}

func parseStat(data []byte) (comm string, state byte, parentPID int, startTime uint64, err error) {
	line := strings.TrimSpace(string(data))
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open < 1 || close <= open || close+2 >= len(line) {
		return "", 0, 0, 0, errors.New("malformed process stat")
	}
	comm = line[open+1 : close]
	fields := strings.Fields(line[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return "", 0, 0, 0, errors.New("malformed process stat")
	}
	state = fields[0][0]
	parentPID, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, 0, 0, errors.New("malformed process parent PID")
	}
	startTime, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, 0, 0, errors.New("malformed process start time")
	}
	return comm, state, parentPID, startTime, nil
}

func currentAncestors() map[int]bool {
	ancestors := make(map[int]bool)
	pid := os.Getpid()
	for pid > 1 {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		_, _, parent, _, err := parseStat(data)
		if err != nil || parent <= 0 || ancestors[parent] {
			break
		}
		ancestors[parent] = true
		pid = parent
	}
	return ancestors
}

func sanitizeDisplay(value string, limit int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, char := range value {
		if unicode.IsControl(char) {
			builder.WriteByte(' ')
		} else {
			builder.WriteRune(char)
		}
		if builder.Len() >= limit {
			break
		}
	}
	result := strings.Join(strings.Fields(builder.String()), " ")
	if len(value) > limit && result != "" {
		result += "..."
	}
	return result
}
