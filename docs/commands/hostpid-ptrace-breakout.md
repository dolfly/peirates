# HostPID ptrace command breakout

## Menu entry

- **Menu item:** `32`
- **Canonical command:** `hostpid-ptrace-breakout`
- **Aliases:** None
- **Maturity:** Experimental; Linux AMD64 only

## Purpose

Run one bounded operator-supplied command in the namespaces, credentials, and
filesystem context of an explicitly selected disposable root process visible
from a `hostPID: true` container. Peirates creates a separate traced child and
restores and detaches the selected process before that child executes
`/bin/sh -c`.

This command does not start an interactive or reverse shell. On a nested
platform such as Kind, matching visible PID 1 establishes the Kind node
container boundary, not necessarily the physical machine.

## Prerequisites and authorization

The first release requires:

- Linux AMD64, effective UID 0, and a readable procfs;
- the current PID and user namespaces to match visible PID 1;
- effective `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` (`SYS_PTRACE` and `SYS_ADMIN`
  in a Kubernetes security context);
- a kernel with `PTRACE_SEIZE`, fork/clone and exec tracing, and pidfds;
- a target root containing executable `/bin/sh`; and
- an explicitly selected, disposable, single-threaded root process that
  matches visible PID 1's PID, user, mount, UTS, IPC, network, cgroup, optional
  time, and filesystem-root identities.

PID 1, Peirates, its ancestors, kernel threads, multithreaded processes,
already traced processes, nested PID-namespace processes, non-root processes,
and stopped, dead, zombie, uninterruptible, or core-dumping processes are
ineligible. Peirates never changes Yama, seccomp, AppArmor, or SELinux policy.
Yama `ptrace_scope=3` is a hard failure.

Use this command only on systems where host-process tracing and host command
execution are explicitly authorized. Select a process created specifically
for this operation, such as a bounded `sleep`, never an existing service.

## Usage

Select item `32` or its canonical command:

```text
32
hostpid-ptrace-breakout
```

Peirates performs read-only qualification, labels matching processes
`Eligible disposable targets`, and prompts:

```text
Disposable host PID to trace: 1234
Single host command: id; hostname; pwd
Type TRACE-DISPOSABLE-HOST-PROCESS-1234 to continue: TRACE-DISPOSABLE-HOST-PROCESS-1234
```

No target is automatically selected. The confirmation phrase is exact and
PID-specific. End-of-file, a PID absent from the eligible list, an empty
command, a NUL byte, a command over 4096 bytes, or any other confirmation
cancels before attach. Direct module mode uses the same prompts and is not an
unattended interface:

```sh
printf '1234\nid; hostname; pwd\nTRACE-DISPOSABLE-HOST-PROCESS-1234\n' |
  peirates -c -m hostpid-ptrace-breakout
```

## What it does

The parent process performs qualification twice and passes the selected PID,
expected start time and identities, command, timeout, and output limit to a
private Peirates re-exec through an inherited anonymous pipe. The command is
not placed in argv, environment variables, or status output. The worker
revalidates every target invariant immediately before attach.

The AMD64 worker locks its OS thread, opens a pidfd for the target, creates a
random mode-`0600` output file beneath the selected root's `/tmp`, then uses
`PTRACE_SEIZE` and `PTRACE_INTERRUPT`. It saves and verifies the complete
general register state and the private executable instruction word it
temporarily patches with a fixed `syscall`/trap sequence. Only a fixed internal
syscall allowlist is available; operator-supplied machine code and syscall
numbers are never accepted.

The worker allocates verified scratch data and invokes `clone` without
`CLONE_VM` or `CLONE_THREAD`. It immediately opens a pidfd for the exact child
and applies `PTRACE_O_EXITKILL` to that child only. The original target never
receives `PTRACE_O_EXITKILL`. Peirates then unmaps its scratch allocation from
the original, restores and verifies the original instruction bytes and
registers, and detaches it before allowing the child to begin command setup.

The child changes to `/`, redirects stdin from `/dev/null`, redirects combined
stdout and stderr to the pre-created file, applies a file-size limit, and
executes `/bin/sh -c` with only `HOME`, `USER`, `LOGNAME`, `SHELL`, and `PATH`.
The default command timeout is 30 seconds and displayed output is limited to
1 MiB. Peirates reports the command exit code or terminating signal separately
from restoration and artifact-cleanup results.

## Expected output

Before mutation Peirates prints a status line similar to:

```text
[hostpid-ptrace-breakout] tracing disposable host PID 1234 to run one command in visible PID 1's namespaces
```

After bounded combined command output, Peirates prints an exit code or signal
and explicit cleanup evidence:

```text
Host command exit code: 0
Target restoration: restored=true detached=true; output artifact removed=true
```

Do not infer a physical-host escape from command output alone. Verify the
hostname, namespace links, filesystem root, and target identity independently.

## Side effects and cleanup

**Warning:** ptrace temporarily stops and modifies a live process. Ordinary
success and handled errors restore the saved bytes and registers, detach the
original target, kill an unfinished injected child through its pidfd, and
remove only the capture path whose device/inode identity still matches the
retained file descriptor.

This cannot be transactional. `SIGKILL` of the worker, a runtime crash, kernel
failure, forced container termination, or node loss during the patched window
can leave the selected process corrupted, stopped, or terminated. That
residual risk is why only a deliberately disposable target is permitted.

The command creates no service, reverse shell, setuid file, cron job, or other
persistence. Commands executed by the child can still modify or destroy host
state and remain the operator's responsibility.

## Failure modes

- Non-Linux or non-AMD64 builds return a precise unsupported error.
- Missing UID, capabilities, hostPID visibility, compatible user namespace,
  proc metadata, pidfd support, or host `/bin/sh` fails closed.
- Yama mode 3 rejects the action; other Yama, seccomp, and LSM policies may
  still reject the real `PTRACE_SEIZE` operation.
- A target that exits, changes start time or identity, becomes multithreaded,
  starts core dumping, or becomes traced between prompts is rejected.
- Ordinary signal-delivery stops for the injected child are reinjected, and
  expected exec/exit events continue normally. Unexpected ptrace events abort
  the operation. A pending external signal observed while stopping the original
  target is preserved for reinjection when detaching it after restoration.
- A command timeout kills only the pidfd-identified injected child, never the
  selected original process.
- Restoration or detach failure takes precedence over a successful command
  result and warns that the disposable target may be damaged.
- A changed output path is never blindly deleted; Peirates reports the
  identity mismatch for manual inspection.

## Implementation and tests

- [HostPID ptrace module](../../internal/modules/hostpidptrace)
- [Application prompts](../../internal/app/hostpid_ptrace.go)
- [Private worker routing](../../internal/app/run.go)
- [Container escape scanner](../../internal/modules/containerescape)
- [Unit tests](../../internal/modules/hostpidptrace/engine_linux_amd64_test.go)
- [Disposable Kind mechanics test](../../test/hostpid-ptrace-breakout-kind-integration.sh)
- [Approved implementation plan](../plans/hostpid-ptrace-breakout.md)

The Kind test validates only the disposable Kind node boundary. A disposable,
independent-kernel VM with a directly installed Kubernetes node remains the
release gate for an outside-all-containers host claim.
