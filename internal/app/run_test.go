package app

import (
	"os"
	"reflect"
	"testing"
)

func TestRunArgsRoutesProcessModes(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	tests := []struct {
		name, wantMode             string
		args, wantArgs             []string
		wantHostPIDWorkerArg       []string
		wantHostPIDPtraceWorkerArg []string
		wantHostRootWorkerArg      []string
	}{
		{name: "peirates", args: []string{"/usr/local/bin/peirates", "-m", "pwd"}, wantMode: "peirates", wantArgs: []string{"/usr/local/bin/peirates", "-m", "pwd"}},
		{name: "kubectl flag", args: []string{"peirates", "--kubectl", "get", "pods"}, wantMode: "kubectl", wantArgs: []string{"kubectl", "get", "pods"}},
		{name: "kubectl basename", args: []string{"/usr/local/bin/kubectl", "get", "nodes"}, wantMode: "kubectl", wantArgs: []string{"/usr/local/bin/kubectl", "get", "nodes"}},
		{name: "hostPID worker", args: []string{"peirates", "--internal-hostpid-worker"}, wantMode: "hostpid", wantArgs: []string{"peirates", "--internal-hostpid-worker"}},
		{name: "hostPID worker rejects extras", args: []string{"peirates", "--internal-hostpid-worker", "extra"}, wantMode: "hostpid", wantArgs: []string{"peirates", "--internal-hostpid-worker", "extra"}, wantHostPIDWorkerArg: []string{"extra"}},
		{name: "hostPID ptrace worker", args: []string{"peirates", "--internal-hostpid-ptrace-worker"}, wantMode: "hostpid-ptrace", wantArgs: []string{"peirates", "--internal-hostpid-ptrace-worker"}},
		{name: "hostPID ptrace worker rejects extras", args: []string{"peirates", "--internal-hostpid-ptrace-worker", "extra"}, wantMode: "hostpid-ptrace", wantArgs: []string{"peirates", "--internal-hostpid-ptrace-worker", "extra"}, wantHostPIDPtraceWorkerArg: []string{"extra"}},
		{name: "host-root worker", args: []string{"peirates", "--internal-hostroot-worker", "/hostroot", "2", "1"}, wantMode: "hostroot", wantArgs: []string{"peirates", "--internal-hostroot-worker", "/hostroot", "2", "1"}, wantHostRootWorkerArg: []string{"/hostroot", "2", "1"}},
		{name: "host-root worker rejects missing target", args: []string{"peirates", "--internal-hostroot-worker"}, wantMode: "hostroot", wantArgs: []string{"peirates", "--internal-hostroot-worker"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode := ""
			var hostPIDWorkerArgs []string
			var hostPIDPtraceWorkerArgs []string
			var hostRootWorkerArgs []string
			RunArgs(test.args, Entrypoints{
				Peirates: func() { mode = "peirates" },
				Kubectl:  func() { mode = "kubectl" },
				HostPIDWorker: func(args []string) {
					mode = "hostpid"
					hostPIDWorkerArgs = append([]string(nil), args...)
				},
				HostRootWorker: func(args []string) {
					mode = "hostroot"
					hostRootWorkerArgs = append([]string(nil), args...)
				},
				HostPIDPtraceWorker: func(args []string) {
					mode = "hostpid-ptrace"
					hostPIDPtraceWorkerArgs = append([]string(nil), args...)
				},
			})
			if mode != test.wantMode {
				t.Fatalf("mode = %q, want %q", mode, test.wantMode)
			}
			if !reflect.DeepEqual(os.Args, test.wantArgs) {
				t.Fatalf("os.Args = %#v, want %#v", os.Args, test.wantArgs)
			}
			if test.wantMode == "hostpid" && !reflect.DeepEqual(hostPIDWorkerArgs, test.wantHostPIDWorkerArg) {
				t.Fatalf("hostPID worker args = %#v, want %#v", hostPIDWorkerArgs, test.wantHostPIDWorkerArg)
			}
			if test.wantMode == "hostroot" && !reflect.DeepEqual(hostRootWorkerArgs, test.wantHostRootWorkerArg) {
				t.Fatalf("host-root worker args = %#v, want %#v", hostRootWorkerArgs, test.wantHostRootWorkerArg)
			}
			if test.wantMode == "hostpid-ptrace" && !reflect.DeepEqual(hostPIDPtraceWorkerArgs, test.wantHostPIDPtraceWorkerArg) {
				t.Fatalf("hostPID ptrace worker args = %#v, want %#v", hostPIDPtraceWorkerArgs, test.wantHostPIDPtraceWorkerArg)
			}
		})
	}
}
