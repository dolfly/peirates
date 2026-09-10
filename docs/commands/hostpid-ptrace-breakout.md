# HostPID ptrace interactive breakout

## Menu entry

- **Menu item:** `32`
- **Canonical command:** `hostpid-ptrace-breakout`
- **Aliases:** None
- **Maturity:** Experimental; Linux AMD64 only

## Purpose

Open an interactive `/bin/sh` in the namespaces, credentials, and filesystem
context of an explicitly selected disposable root process visible from a
`hostPID: true` container. Peirates creates a separate traced child, restores
and detaches the selected process, and only then allows the child to execute
the shell.

On a nested platform such as Kind, matching visible PID 1 establishes the Kind
node container boundary, not necessarily the physical machine.

## Prerequisites and authorization

This command requires:

- Linux AMD64, effective UID 0, and a readable procfs;
- the current PID and user namespaces to match visible PID 1;
- effective `CAP_SYS_PTRACE` (`SYS_PTRACE` in a Kubernetes security context);
- a kernel with `PTRACE_SEIZE`, fork/clone and exec tracing, and pidfds;
- a target root containing executable `/bin/sh` and a working devpts mount;
  and
- an explicitly selected, disposable, single-threaded root process that
  matches visible PID 1's PID, user, mount, UTS, IPC, network, cgroup, optional
  time, and filesystem-root identities.

`CAP_SYS_ADMIN` is not required by this technique.

PID 1, Peirates, its ancestors, kernel threads, multithreaded processes,
already traced processes, nested PID-namespace processes, non-root processes,
and stopped, dead, zombie, uninterruptible, or core-dumping processes are
ineligible. Peirates never changes Yama, seccomp, AppArmor, or SELinux policy.
Yama `ptrace_scope=3` is a hard failure.

Use this command only where tracing and host-shell access are explicitly
authorized. Select a process created specifically for this operation, such as
a bounded `sleep`, never an existing service.

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
Type TRACE-DISPOSABLE-HOST-PROCESS-1234 to continue: TRACE-DISPOSABLE-HOST-PROCESS-1234
```

No target is automatically selected. The confirmation phrase is exact and
PID-specific. End-of-file, a PID absent from the eligible list, or any other
confirmation cancels before attach.

After confirmation, Peirates opens an interactive PTY-backed `/bin/sh -i`.
Enter `exit` or send end-of-file to leave it. When Peirates is attached to a
terminal, it temporarily enables raw input and propagates terminal resize
events. Direct module mode uses the same prompts and can also accept scripted
input, for example:

```sh
printf '1234\nTRACE-DISPOSABLE-HOST-PROCESS-1234\nid\nexit\n' |
  peirates -c -m hostpid-ptrace-breakout
```

## What it does

The application qualifies the target twice. It then opens `/dev/ptmx` through
the selected target's root, unlocks a new PTY slave, and records the slave's
device, inode, and device ID. The parent retains the PTY master and sends only
the selected target evidence and PTY identity to a private Peirates re-exec
through an inherited anonymous pipe. Interactive input is relayed through the
PTY and is not placed in argv, environment variables, the worker protocol, or
status output.

The AMD64 worker locks its OS thread, revalidates every target invariant and
the PTY identity, then uses `PTRACE_SEIZE` and `PTRACE_INTERRUPT`. It saves and
verifies the complete general register state and the private executable
instruction word it temporarily patches with a fixed `syscall`/trap sequence.
Only a fixed internal syscall allowlist is available; operator-supplied machine
code and syscall numbers are never accepted.

The worker allocates verified scratch data and invokes `clone` without
`CLONE_VM` or `CLONE_THREAD`. It immediately opens a pidfd for the exact child
and applies `PTRACE_O_EXITKILL` to that child only. The original target never
receives `PTRACE_O_EXITKILL`. Peirates then unmaps its scratch allocation from
the original, restores and verifies the original instruction bytes and
registers, and detaches it before allowing the child to begin shell setup.

The child creates a new session, changes to `/`, opens the verified PTY slave,
makes it the controlling terminal, redirects file descriptors 0, 1, and 2 to
it, and executes `/bin/sh -i`. The shell receives only `HOME`, `USER`,
`LOGNAME`, `SHELL`, `TERM`, and `PATH`. Peirates relays input and output until
the shell exits and then reports the exit code or terminating signal separately
from the original target's restoration result.

## Expected output

Before mutation Peirates prints a status line similar to:

```text
[hostpid-ptrace-breakout] tracing disposable host PID 1234 to open an interactive shell in visible PID 1's namespaces
```

After the shell exits, Peirates reports its status and cleanup evidence:

```text
Interactive host shell exit code: 0
Target restoration: restored=true detached=true
```

Do not infer a physical-host escape from shell output alone. Verify the
hostname, namespace links, filesystem root, and target identity independently.

## Side effects and cleanup

**Warning:** ptrace temporarily stops and modifies a live process. Ordinary
success and handled errors restore the saved bytes and registers, detach the
original target, and kill an unfinished injected child through its pidfd. The
PTY slave exists only while its master is open; this implementation creates no
capture file.

This cannot be transactional. `SIGKILL` of the worker, a runtime crash, kernel
failure, forced container termination, or node loss during the patched window
can leave the selected process corrupted, stopped, or terminated. That
residual risk is why only a deliberately disposable target is permitted.

The command creates no service, reverse shell, setuid file, cron job, or other
persistence. Commands entered in the shell can still modify or destroy host
state and remain the operator's responsibility.

## Failure modes

- Non-Linux or non-AMD64 builds return a precise unsupported error.
- Missing UID, capabilities, hostPID visibility, compatible user namespace,
  proc metadata, pidfd support, target `/bin/sh`, or target devpts fails closed.
- Yama mode 3 rejects the action; other Yama, seccomp, and LSM policies may
  still reject the real `PTRACE_SEIZE` operation.
- A target that exits, changes start time or identity, becomes multithreaded,
  starts core dumping, or becomes traced between prompts is rejected.
- A PTY slave whose identity changes before attach is rejected.
- Ordinary signal-delivery stops for the injected child are reinjected, and
  expected exec/exit events continue normally. Unexpected ptrace events abort
  the operation. A pending external signal observed while stopping the
  original target is preserved for reinjection when detaching it.
- Cancellation or terminal loss kills only the pidfd-identified injected
  child, never the selected original process.
- Restoration or detach failure takes precedence over a successful shell
  result and warns that the disposable target may be damaged.

## Implementation and tests

- [HostPID ptrace module](../../internal/modules/hostpidptrace)
- [Application prompts](../../internal/app/hostpid_ptrace.go)
- [Private worker routing](../../internal/app/run.go)
- [Container escape scanner](../../internal/modules/containerescape)
- [Unit tests](../../internal/modules/hostpidptrace/engine_linux_amd64_test.go)
- [Disposable Kind mechanics test](../../test/hostpid-ptrace-breakout-kind-integration.sh)
- [Implementation plan](../plans/hostpid-ptrace-breakout.md)

The Kind test validates only the disposable Kind node boundary. A disposable,
independent-kernel VM with a directly installed Kubernetes node remains the
release gate for an outside-all-containers host claim.
