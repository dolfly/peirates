// Package hostroot implements entry into an explicitly mounted host root.
package hostroot

import "errors"

// WorkerArgument selects the isolated host-root worker process. It is an
// internal process mode, not a supported user-facing command-line option.
const WorkerArgument = "--internal-hostroot-worker"

const outputPrefix = "[hostroot-breakout]"

// ErrUnsupported is returned on operating systems without chroot support.
var ErrUnsupported = errors.New("host-root breakout is supported only on Linux")

func shellEnvironment(term string) []string {
	environment := []string{
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PS1=[peirates-hostroot]# ",
	}
	if term != "" {
		environment = append(environment, "TERM="+term)
	}
	return environment
}
