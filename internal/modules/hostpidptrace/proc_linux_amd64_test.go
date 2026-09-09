//go:build linux && amd64

package hostpidptrace

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseStatus(t *testing.T) {
	data := []byte("State:\tS (sleeping)\nUid:\t0\t0\t0\t0\nThreads:\t1\nTracerPid:\t0\nCoreDumping:\t0\nNSpid:\t123\nSeccomp:\t2\nCapEff:\t0000000000280000\n")
	status, err := parseStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if status.state != 'S' || status.uids != [4]uint32{} || status.threads != 1 || status.tracerPID != 0 || status.coreDumping != 0 || status.pidDepth != 1 || status.seccomp != 2 || !status.hasCapEff {
		t.Fatalf("status = %#v", status)
	}
}

func TestParseStatusRejectsMissingAndMalformedFields(t *testing.T) {
	base := "State:\tS\nUid:\t0\t0\t0\t0\nThreads:\t1\nTracerPid:\t0\nCoreDumping:\t0\nNSpid:\t1\n"
	for _, data := range []string{
		strings.Replace(base, "Threads:\t1\n", "", 1),
		strings.Replace(base, "Uid:\t0\t0\t0\t0", "Uid:\t0\tbad\t0\t0", 1),
	} {
		if _, err := parseStatus([]byte(data)); err == nil {
			t.Fatalf("malformed status was accepted: %q", data)
		}
	}
}

func TestParseStatHandlesSpacesAndClosingParenthesisInComm(t *testing.T) {
	fields := []string{"S", "7"}
	for len(fields) < 20 {
		fields = append(fields, "0")
	}
	fields[19] = "98765"
	data := fmt.Sprintf("123 (worker ) name) %s\n", strings.Join(fields, " "))
	comm, state, parent, start, err := parseStat([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if comm != "worker ) name" || state != 'S' || parent != 7 || start != 98765 {
		t.Fatalf("stat = %q %c %d %d", comm, state, parent, start)
	}
}

func TestSanitizeDisplayRedactsControlsAndBounds(t *testing.T) {
	got := sanitizeDisplay("alpha\x00beta\n"+strings.Repeat("x", 40), 20)
	if strings.ContainsAny(got, "\x00\n") || len(got) > 23 || !strings.HasSuffix(got, "...") {
		t.Fatalf("sanitized display = %q", got)
	}
}

func TestIdentityMapsEqual(t *testing.T) {
	left := map[string]Identity{"pid": {Device: 1, Inode: 2}}
	if !identityMapsEqual(left, map[string]Identity{"pid": {Device: 1, Inode: 2}}) {
		t.Fatal("equal maps differed")
	}
	if identityMapsEqual(left, map[string]Identity{"pid": {Device: 1, Inode: 3}}) {
		t.Fatal("different maps matched")
	}
}

func TestCandidateMetadataRejectionClasses(t *testing.T) {
	base := processStatus{state: 'S', threads: 1, coreDumping: 0, pidDepth: 1}
	tests := []struct {
		name       string
		status     processStatus
		tasks      int
		executable string
		execErr    error
		want       string
	}{
		{name: "eligible", status: base, tasks: 1, executable: "/bin/sleep"},
		{name: "non-root", status: func() processStatus { value := base; value.uids[1] = 1; return value }(), tasks: 1, executable: "/bin/sleep", want: "non-root"},
		{name: "status threads", status: func() processStatus { value := base; value.threads = 2; return value }(), tasks: 2, executable: "/bin/sleep", want: "multithreaded"},
		{name: "task threads", status: base, tasks: 2, executable: "/bin/sleep", want: "multithreaded"},
		{name: "traced", status: func() processStatus { value := base; value.tracerPID = 9; return value }(), tasks: 1, executable: "/bin/sleep", want: "already-traced"},
		{name: "core dumping", status: func() processStatus { value := base; value.coreDumping = 1; return value }(), tasks: 1, executable: "/bin/sleep", want: "core-dumping"},
		{name: "uninterruptible", status: func() processStatus { value := base; value.state = 'D'; return value }(), tasks: 1, executable: "/bin/sleep", want: "unsafe-state"},
		{name: "stopped", status: func() processStatus { value := base; value.state = 'T'; return value }(), tasks: 1, executable: "/bin/sleep", want: "unsafe-state"},
		{name: "zombie", status: func() processStatus { value := base; value.state = 'Z'; return value }(), tasks: 1, executable: "/bin/sleep", want: "unsafe-state"},
		{name: "nested", status: func() processStatus { value := base; value.pidDepth = 2; return value }(), tasks: 1, executable: "/bin/sleep", want: "nested-pid"},
		{name: "kernel thread", status: base, tasks: 1, execErr: errors.New("missing"), want: "kernel-thread"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := processMetadataReason(test.status, test.tasks, test.executable, test.execErr)
			if got != test.want {
				t.Fatalf("rejection = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProhibitedTargetRejection(t *testing.T) {
	for _, test := range []struct {
		pid, self int
		ancestors map[int]bool
		want      string
	}{{1, 99, nil, "prohibited-pid"}, {99, 99, nil, "self-or-ancestor"}, {50, 99, map[int]bool{50: true}, "self-or-ancestor"}, {50, 99, nil, ""}} {
		got, _ := prohibitedTargetReason(test.pid, test.self, test.ancestors)
		if got != test.want {
			t.Fatalf("PID %d rejection = %q, want %q", test.pid, got, test.want)
		}
	}
}

func TestRequirePtraceCapabilities(t *testing.T) {
	both := uint64(1)<<uint(unix.CAP_SYS_PTRACE) | uint64(1)<<uint(unix.CAP_SYS_ADMIN)
	if err := requirePtraceCapabilities(both); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		capabilities uint64
		want         string
	}{{uint64(1) << uint(unix.CAP_SYS_ADMIN), "CAP_SYS_PTRACE"}, {uint64(1) << uint(unix.CAP_SYS_PTRACE), "CAP_SYS_ADMIN"}, {0, "CAP_SYS_PTRACE, CAP_SYS_ADMIN"}} {
		if err := requirePtraceCapabilities(test.capabilities); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("capabilities %#x error = %v, want %q", test.capabilities, err, test.want)
		}
	}
}
