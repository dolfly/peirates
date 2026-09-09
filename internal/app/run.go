package app

import (
	"os"
	"path/filepath"

	"github.com/inguardians/peirates/internal/modules/hostpid"
	"github.com/inguardians/peirates/internal/modules/hostpidptrace"
	"github.com/inguardians/peirates/internal/modules/hostproc"
	"github.com/inguardians/peirates/internal/modules/hostroot"
)

// Entrypoints contains the process modes selected by RunArgs.
type Entrypoints struct {
	Peirates            func()
	Kubectl             func()
	HostPIDWorker       func([]string)
	HostPIDPtraceWorker func([]string)
	HostRootWorker      func([]string)
	HostProcWorker      func([]string)
}

// Run starts Peirates using the current process arguments.
func Run() {
	RunArgs(os.Args, Entrypoints{
		Peirates: Main,
		Kubectl:  ExecKubectlAndExit,
		HostPIDWorker: func(args []string) {
			os.Exit(hostpid.RunWorker(args, os.Stdin, os.Stdout, os.Stderr))
		},
		HostPIDPtraceWorker: func(args []string) {
			os.Exit(hostpidptrace.RunInheritedWorker(args, os.Stderr))
		},
		HostRootWorker: func(args []string) {
			os.Exit(hostroot.RunWorker(args, os.Stdin, os.Stdout, os.Stderr))
		},
		HostProcWorker: func(args []string) {
			os.Exit(hostproc.RunCrashWorker(args, os.Stderr))
		},
	})
}

// RunArgs preserves the historical argv routing for normal and kubectl modes.
func RunArgs(args []string, entrypoints Entrypoints) {
	if len(args) == 0 {
		args = []string{"peirates"}
	}
	os.Args = args
	if len(os.Args) > 1 && os.Args[1] == hostpid.WorkerArgument {
		entrypoints.HostPIDWorker(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == hostpidptrace.WorkerArgument {
		entrypoints.HostPIDPtraceWorker(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == hostroot.WorkerArgument {
		entrypoints.HostRootWorker(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == hostproc.CrashWorkerArgument {
		entrypoints.HostProcWorker(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--kubectl" {
		os.Args = append([]string{"kubectl"}, os.Args[2:]...)
		entrypoints.Kubectl()
		return
	}
	if filepath.Base(os.Args[0]) == "kubectl" {
		entrypoints.Kubectl()
		return
	}
	entrypoints.Peirates()
}
