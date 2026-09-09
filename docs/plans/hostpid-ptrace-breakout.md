# HostPID ptrace breakout plan

Status: **IMPLEMENTED — INDEPENDENT-KERNEL VM VALIDATION PENDING.** The approved
design is implemented with unit and integration harness coverage. On
2026-09-09, the Linux AMD64 engine test passed against a disposable process
created and owned by the test, including command output, target identity,
restoration, detach, and artifact-removal assertions. The disposable Kind
mechanics test also passed on 2026-09-09, including both dispatch forms,
namespace/output evidence, negative controls, timeout, and fail-closed cleanup.
The independent-kernel VM acceptance test has not yet been run; do not claim an
outside-all-containers breakout until that gate passes.

## Goal

Add an experimental Peirates command that can run one operator-supplied command
in the namespaces and filesystem context of an explicitly selected root process
visible from a `hostPID: true` container. The intended Kubernetes container is
root, shares the node PID namespace, and has `SYS_PTRACE` and `SYS_ADMIN` in its
container capability list.

The canonical command is:

```text
hostpid-ptrace-breakout
```

The implementation uses menu item `32` and does not add aliases in the first
release.

## Decision: run one command, not an interactive shell

The first release should run a single command through the target host's
`/bin/sh -c`, capture bounded standard output and standard error, report the
exit status, and terminate the injected child.

An interactive shell is intentionally out of scope. A ptrace-created process
does not naturally inherit Peirates' terminal file descriptors. Relaying a
terminal would require another host-visible transport, descriptor passing, PTY
allocation, more long-lived state, and substantially more failure cleanup. A
single command provides the requested host execution primitive with a shorter
trace window and a testable terminal condition.

Interactive access may receive a separate proposal after the command runner is
proven safe. It must not be added opportunistically during this implementation.

## Terminology and capability contract

The Linux capability is `CAP_SYS_PTRACE`. Kubernetes manifests omit the
`CAP_` prefix, so the container security context spells the requested
capabilities as:

```yaml
spec:
  hostPID: true
  containers:
    - name: peirates
      securityContext:
        runAsUser: 0
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
```

`CAP_SYS_PTRACE` is the capability that authorizes tracing arbitrary processes
and accessing protected `/proc/<pid>` data. `CAP_SYS_ADMIN` is retained as an
explicit eligibility requirement because it is part of the requested scenario,
but the ptrace execution engine must not use it to fall back to `setns`, mount,
or chroot behavior. The existing `hostpid-breakout` command already owns the
`setns`/chroot design.

Capabilities are evaluated in relation to user namespaces. Peirates must have
`CAP_SYS_PTRACE` in the target's user namespace; having that capability only in
a nested container user namespace is insufficient. The implementation must
compare the current, PID 1, and target user-namespace identities and fail closed
when they differ.

Primary references:

- [Linux `ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux namespace handles](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Linux PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [Linux `/proc/<pid>/status`](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [Linux Yama ptrace policy](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [Kubernetes capability syntax](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

## Security model and hard limitation

`ptrace` temporarily stops a live thread and permits Peirates to replace its
registers and instruction bytes. Peirates can save and restore that state on an
ordinary success or handled error, but it cannot make the operation
transactional. A Peirates crash, kernel failure, forced container termination,
or node failure during the patched interval can leave the selected process
corrupted, stopped, or terminated.

Therefore:

- the operator must select the target explicitly;
- the UI must label candidates **eligible**, never **safe**;
- PID 1 is always prohibited;
- the Peirates process, its ancestors, kernel threads, already traced tasks,
  multithreaded processes, and non-root processes are prohibited;
- the confirmation must state that the target can be damaged or killed; and
- documentation and tests must use a deliberately disposable, single-threaded
  host process such as a dedicated `sleep`, never an existing service.

The implementation must not include a fallback that replaces the original
process with a shell or command. If a child cannot be created while preserving
and detaching the original target, stop and request a separate design review.

## Boundary definition

The local implementation cannot prove that a process is outside every possible
container solely from `/proc`. For this command, "initial host namespaces"
means that the target matches the visible PID 1 in all namespace and root
identities Peirates can compare. On a nested platform such as Kind, that boundary
may be the Kind node container rather than the physical machine.

Before presenting a target as eligible, compare it with visible PID 1 for:

- PID, user, mount, UTS, IPC, network, and cgroup namespace device/inode
  identities;
- time namespace identity when that namespace entry is available;
- filesystem-root device/inode identity; and
- PID-namespace depth through the `NSpid` or `NStgid` values in
  `/proc/<pid>/status`.

Every required identity must match. An unavailable mandatory identity is an
error, not a reason to weaken classification. The time namespace may be treated
as optional only on kernels that do not expose it for PID 1 or the target.

The UI must show this limitation before confirmation and identify the matched
boundary as "visible PID 1's namespaces", not claim an infallible physical-host
escape.

## Supported platform

Version one is Linux AMD64 only:

- `GOOS=linux`, `GOARCH=amd64`;
- x86-64 register layout and syscall ABI;
- `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, fork/clone tracing, and exec tracing;
- `pidfd_open` and `pidfd_send_signal`; and
- a host `/bin/sh` visible through the selected target's root.

Architecture-specific injection must live behind `linux && amd64` build tags.
Other platforms return a precise unsupported error without attempting ptrace.
Validation for this feature must compile only the AMD64 variation unless the
operator later requests other architectures.

Requiring pidfds deliberately sets a modern-kernel floor. Do not add a numeric
PID-only signal fallback because PID reuse could direct cleanup at the wrong
host process.

## Read-only preflight

The initial probe and candidate listing must not attach to, stop, signal, or
write memory in any process.

### Current process checks

Require:

1. Linux AMD64.
2. Effective UID 0.
3. Effective `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN`, parsed from
   `/proc/self/status`.
4. The current PID namespace identity to equal visible PID 1's PID namespace,
   establishing the observable `hostPID` prerequisite.
5. The current user namespace identity to equal visible PID 1's user namespace.
6. A readable procfs that exposes PID 1 and numeric host processes.
7. `pidfd_open` support.

Read `/proc/sys/kernel/yama/ptrace_scope` when available. Never modify it.
Value `3` is an immediate unsupported-policy failure because Yama forbids
attach operations even for capable processes. Other values remain subject to
the real attach check and any additional LSM.

Read and display the current process's seccomp mode and detected AppArmor or
SELinux label when available. A filter is a warning rather than proof of
failure; the actual `PTRACE_SEIZE` result remains authoritative. Never disable
seccomp or alter an LSM policy.

### Candidate enumeration

Enumerate numeric `/proc/<pid>` entries, sort numerically, and collect all
candidate metadata from opened descriptors rather than trusting pathnames after
the fact. For each candidate, parse and show:

- PID, start time, `comm`, executable path, and a sanitized/truncated command
  line;
- real, effective, saved-set, and filesystem UIDs;
- process state, thread count, `TracerPid`, and `CoreDumping`;
- `NSpid`/`NStgid` depth;
- namespace identity comparison results;
- root identity comparison result; and
- whether `/bin/sh` is executable through the target root.

An eligible target must satisfy all of the following:

- PID greater than 1;
- not Peirates and not any Peirates ancestor;
- all four UIDs are zero;
- exactly one thread in `/proc/<pid>/task` and `Threads: 1`;
- `TracerPid: 0` and `CoreDumping: 0`;
- not zombie, dead, uninterruptible sleep, or already stopped;
- has a user-space executable and is not a kernel thread;
- has exactly the same required namespaces and root as visible PID 1;
- has a single initial PID-namespace level in the selected procfs view;
- exposes an executable `/bin/sh` through its root; and
- can be represented by a pidfd and a stable `/proc/<pid>/stat` start time.

No target is auto-selected, even if exactly one qualifies. Empty results should
explain which qualification classes rejected processes without dumping
sensitive full command lines.

## Proposed interaction

The application layer should:

1. Print the capability and namespace caveat.
2. List eligible targets as PID, `comm`, executable, and truncated command line.
3. Prompt `Disposable host PID to trace: `.
4. Revalidate that exact PID and show all qualification evidence.
5. Prompt `Single host command: ` and reject empty input, NUL bytes, and input
   over 4096 bytes.
6. Require the exact phrase `TRACE-DISPOSABLE-HOST-PROCESS-<pid>`.
7. Revalidate the target again in the private worker immediately before attach.
8. Print a status line before mutation, for example:

   ```text
   [hostpid-ptrace-breakout] tracing disposable host PID 1234 to run one command in visible PID 1's namespaces
   ```

9. Run the command, print bounded combined output, then print the exit code or
   terminating signal and a target-restoration result.

EOF or any incorrect confirmation cancels without attaching. Direct module mode
uses the same prompts and line-oriented input. Do not place the command in
process arguments, environment variables, status lines, or ordinary logs.

## Process architecture

Use a parent/worker split similar to `hostpid-breakout`:

- The normal Peirates process owns prompts, display, and final reporting.
- A private re-exec mode performs all ptrace and wait operations.
- The private mode is dispatched before normal application initialization.
- The worker receives a length-bounded request through an inherited anonymous
  pipe, not argv or environment, so the command is not exposed through process
  listings.
- The worker calls `runtime.LockOSThread` before its first ptrace operation and
  remains on that OS thread until every tracee is detached or reaped.
- The worker returns structured stage/result information to the parent through
  a second pipe. Human output remains the application's responsibility.

The request contains only the selected PID, expected start time and identities,
command, timeout, and output limit. Treat malformed, duplicate, or trailing
protocol data as an internal error.

## Host output transport

Before attaching, open and retain the selected root directory through
`/proc/<pid>/root`. Create a cryptographically random output file beneath the
target's `/tmp` using descriptor-relative, no-follow, exclusive creation and
mode `0600`. Record its device/inode identity and retain Peirates' open file
descriptor.

The injected child opens the corresponding host path, redirects stdout and
stderr there, redirects stdin from `/dev/null`, and executes the command. On
completion Peirates reads through its retained descriptor, enforcing a default
1 MiB display limit.

The child must apply `RLIMIT_FSIZE` before `execve` so a command cannot grow the
capture file without bound. Cleanup unlinks only the exact descriptor-relative
path if its identity still matches. An identity mismatch is reported and never
blindly deleted.

## AMD64 ptrace engine

Implement ptrace behind a narrow internal interface so event sequencing and
rollback can be unit-tested without controlling real processes.

### Attach and snapshot

1. Open a pidfd for the target and repeat every eligibility check.
2. Call `PTRACE_SEIZE`; do not use `PTRACE_ATTACH`, because the latter sends a
   real `SIGSTOP` and introduces avoidable stop-signal races.
3. Call `PTRACE_INTERRUPT` and wait with a bounded timeout for the expected
   `PTRACE_EVENT_STOP`.
4. Reject unexpected signal-delivery stops unless they can be preserved for
   reinjection during detach.
5. Save the complete general-purpose register set.
6. Confirm the instruction pointer is in a private executable user mapping,
   save every word that will be modified, and verify each saved word by a
   second read.
7. Enable only fork/clone event tracing on the original target. Never set
   `PTRACE_O_EXITKILL` on the original process: that option would kill the host
   target if Peirates exited.

### Remote syscall primitive

For AMD64, use a minimal temporary `syscall`/trap sequence at the stopped
instruction pointer. Save and restore whole machine words because ptrace writes
are word-oriented. Set syscall number and arguments according to the x86-64
ABI, continue only the stopped thread, wait for the exact expected trap, and
decode negative syscall returns as errno values.

The primitive must:

- allow only a fixed internal syscall allowlist;
- have a per-operation timeout;
- treat any unexpected wait status or signal as an abort;
- never accept operator-supplied machine code or syscall numbers; and
- preserve a pending external signal for correct reinjection after restoring
  the target.

Use it first to allocate a scratch mapping for fixed payload data, argv,
environment, paths, and resource-limit structures. Verify all remote writes by
reading them back.

### Create a disposable command child

Use the tracee's clone syscall without `CLONE_VM` or `CLONE_THREAD`. Include
`CLONE_PARENT` and `SIGCHLD` so the original target does not become responsible
for reaping the command child. Enable both fork and clone ptrace events and
accept only the event PID returned by `PTRACE_GETEVENTMSG`.

The new child starts ptrace-stopped and inherits the target's credentials,
filesystem context, namespaces, and copied memory. Immediately:

1. Open a pidfd for the exact child.
2. Set `PTRACE_O_EXITKILL`, `PTRACE_O_TRACEEXEC`, and `PTRACE_O_TRACEEXIT` on
   the child only.
3. Confirm the child namespace and root identities still match the target.
4. Unmap scratch memory from the original process.
5. Restore and verify every modified original-process instruction word.
6. Restore the complete original register set.
7. Detach the original with any preserved pending signal.

The original target must be restored and detached before the child begins
command setup. If restoration cannot be verified, stop, report the target as
potentially damaged, and do not claim success.

### Configure and exec the child

Using only fixed remote syscalls and data already written to scratch memory:

1. Set a descriptive process name.
2. Change directory to `/`.
3. Open `/dev/null` for stdin.
4. Open the pre-created output path without following symlinks.
5. Redirect file descriptors 0, 1, and 2 and close temporary descriptors.
6. Apply the output file-size limit.
7. Execute `/bin/sh` with `argv = ["sh", "-c", command]` and a minimal
   environment containing only `HOME`, `USER`, `LOGNAME`, `SHELL`, and `PATH`.

Successful exec must be observed as `PTRACE_EVENT_EXEC`. Continue the child and
wait for its real exit or signal. Report status exactly. A failed setup or exec
must use a fixed 126/127-style exit code; it must not return into the copied host
program.

On timeout or cancellation, send `SIGKILL` through the child's pidfd, continue
it if ptrace-stopped, and reap the ptrace event. Never signal the original
target during child cleanup.

## Cleanup state machine

Represent mutation as explicit monotonic stages rather than scattered deferred
calls:

```text
qualified
  -> output-created
  -> target-seized
  -> target-stopped
  -> target-patched
  -> child-created
  -> child-contained
  -> target-restored
  -> target-detached
  -> child-execed
  -> child-reaped
  -> output-removed
```

Each transition records enough state for the reverse cleanup path. Cleanup
order is:

1. Stop or kill only the exact injected child through its pidfd when created.
2. Restore the original target's instruction bytes and registers while it is
   still stopped.
3. Verify restoration by rereading bytes and registers.
4. Detach the original and reinject a preserved external signal when required.
5. Reap all ptrace events.
6. Close pidfds and target-root descriptors.
7. Remove the output file only after identity verification.

Return the command result separately from cleanup results. Any restoration or
detach failure takes precedence over a successful command exit. Never print a
generic success line unless the original target is confirmed detached and the
output artifact is removed.

Signal handlers in the worker initiate the same bounded cleanup path. The
parent waits for the worker rather than exiting immediately. Document that
`SIGKILL`, runtime crashes, kernel failures, and node loss cannot be recovered.

## File and package layout

Create a separate internal package rather than extending the stable namespace
entry module:

```text
internal/modules/hostpidptrace/
  hostpidptrace.go
  proc.go
  protocol.go
  engine_linux_amd64.go
  unsupported.go
  *_test.go
```

Application wiring:

- `internal/app/hostpid_ptrace.go`: prompts, candidate display, exact
  confirmation, and parent/worker orchestration.
- `internal/app/run.go`: private worker dispatch before application startup.
- `internal/app/dispatch.go`: menu item `32` and canonical command.
- `internal/app/module_registry.go`: command registration.
- `internal/ui/menu.go` and `internal/ui/completion.go`: menu and completion.
- `internal/modules/containerescape`: read-only detection of the hostPID,
  user-namespace, and capability prerequisites.

Documentation and test wiring:

- `docs/commands/hostpid-ptrace-breakout.md`.
- `docs/commands/README.md` and `docs/commands/manifest.tsv`.
- `docs/commands/container-escape-scan.md`.
- `test/hostpid-ptrace-breakout-kind-integration.sh`.
- `test/README.md`, `Makefile`, `test/run-kind-tests.sh`, and
  `.github/workflows/kind.yaml`, preserving exact integration-target inventory
  parity.

Lower-level packages must not import `internal/app`. Reuse only narrow proc,
identity, and capability helpers from existing escape packages; do not create a
new public `pkg` API.

## Unit tests

Add table-driven tests for:

- effective capability parsing and missing `CAP_SYS_PTRACE`/`CAP_SYS_ADMIN`;
- namespace/root identity classification;
- `NSpid`, UID, state, thread-count, `TracerPid`, `CoreDumping`, start-time,
  `comm`, and command-line parsing;
- PID 1, self, ancestor, kernel-thread, multithread, nested-namespace,
  non-root, already-traced, and unstable-PID rejection;
- deterministic numeric sorting and redaction/truncation of candidate output;
- exact confirmation phrase generation and mismatch cancellation;
- worker protocol framing, size bounds, malformed input, and command secrecy;
- AMD64 register/syscall argument construction and errno decoding;
- exact preservation of partially overwritten machine words;
- fork/clone, exec, exit, signal, and unexpected ptrace-event decoding;
- output limit enforcement and output-file identity-safe cleanup; and
- every cleanup stage through fault injection, including failures before and
  after child creation and before and after original-target restoration.

Tests must assert operation ordering: the original process is restored and
detached before the child is allowed to exec. A fake ptrace platform should make
it impossible for tests to pass when cleanup targets a raw reused PID instead
of a pidfd-backed identity.

Add Linux AMD64 subprocess tests against a Peirates-owned disposable child when
the environment permits ptrace. They must skip with a precise reason under
blocking seccomp/LSM policy and must never attach to an unrelated process.

## Integration tests

### Disposable Kind mechanics test

Kind can validate mechanics relative to the node boundary, but it cannot prove
escape to a physical host because the Kind node is itself a container.

The test should:

1. Create a uniquely claimed disposable Kind cluster using the shared
   fail-closed ownership helpers.
2. Build only a static Linux AMD64 Peirates binary.
3. Start a dedicated, single-threaded root `sleep` process inside the Kind node
   container, with a unique command-line marker and a bounded lifetime.
4. Independently record its PID, start time, namespace identities, root
   identity, executable, and command line from Docker.
5. Create a pod with `hostPID: true`, root UID, only `SYS_PTRACE` and
   `SYS_ADMIN` added, and the least-permissive seccomp setting that actually
   permits the required ptrace calls.
6. Run a harmless command that prints a random marker, identity, hostname,
   working directory, and namespace links.
7. Assert output and namespace identities independently against Docker's node
   observations.
8. Verify the original `sleep` PID, start time, executable, and command line are
   unchanged and still running after Peirates detaches.
9. Verify no capture file, traced child, or Peirates process remains.
10. Terminate only the uniquely identified sleep fixture and delete the claimed
    cluster through the shared cleanup trap.

Negative controls must cover:

- no `SYS_PTRACE`;
- no `SYS_ADMIN`;
- private PID namespace;
- nested user namespace when supported;
- target in a pod/container namespace rather than PID 1's full boundary;
- multithreaded target;
- PID 1 selection;
- wrong confirmation;
- target exit between listing and confirmation; and
- command timeout, proving only the injected child is killed.

Do not change the node's Yama, seccomp, AppArmor, or SELinux policy to make a
negative control pass. If policy blocks the positive fixture, report the
environmental limitation and use the independent VM test for positive
coverage.

### Independent-kernel VM acceptance test

The release gate for the claim "outside any containers" is a disposable VM
whose physical node init and sacrificial target are not containerized. Use a
single-node Kubernetes distribution installed directly in that VM, create the
capability-limited hostPID pod, and launch a dedicated root sleep process from
the VM console or service manager.

Independently assert from the VM console that:

- the selected target belongs to the VM's initial namespaces and root;
- the command output matches VM identity and namespace observations;
- the original target survives with the same PID/start time and behavior;
- the injected child terminates;
- no output file remains; and
- the pod and all fixtures are removed.

Never run the positive test against a production node or an existing system
service.

## Validation commands

After implementation, run in this order and without non-AMD64 cross-compiles:

```sh
gofmt -w <changed-go-files>
go test ./internal/modules/hostpidptrace ./internal/app ./internal/modules/containerescape
GOFLAGS=-p=1 make test-quiet
make build
file peirates
git diff --check
```

Then run the dedicated Kind target only in a Docker-ready session, followed by
the independent VM acceptance procedure. Capture the exact ptrace policy,
kernel version, namespace evidence, restoration checks, and cleanup result in
the test report.

## Implementation phases and review gates

### Phase 1: read-only discovery

Implement proc parsing, capability checks, namespace/root classification,
candidate listing, target selection, and confirmation. The command must stop
before `PTRACE_SEIZE`.

Review gate: confirm the candidate set and false-positive behavior on Kind and
an independent VM.

### Phase 2: ptrace restoration spike

Against a Peirates-owned disposable child only, implement seize, interrupt,
register/word snapshot, one harmless remote syscall, restoration, detach, and
fault-injection tests.

Review gate: demonstrate byte-for-byte register and instruction restoration at
every injected failure point. Do not yet target a host process.

### Phase 3: disposable child and one command

Add scratch memory, traced clone, pidfds, immediate original-target restoration,
bounded output transport, `/bin/sh -c`, timeout, and complete cleanup.

Review gate: prove the original disposable process survives repeated success,
failure, cancellation, and timeout runs. If it cannot be preserved reliably,
stop; do not implement destructive replacement as a fallback.

### Phase 4: product wiring and documentation

Add menu item 32, direct-module routing, scan finding, completion, command docs,
and unit/smoke coverage.

Review gate: inspect all operator warnings, confirmation behavior, output
redaction, and unsupported-platform behavior.

### Phase 5: isolated positive validation

Run the Kind mechanics test, then the independent-kernel VM acceptance test.
Do not mark the feature stable from Kind evidence alone.

## Acceptance criteria

The feature is complete only when all of the following are true:

- It runs only on Linux AMD64 and compiles a static AMD64 Peirates binary.
- It requires effective UID 0, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`, observable
  hostPID sharing, and a compatible user namespace.
- It never auto-selects a target and never permits PID 1.
- It rejects multithreaded, already traced, non-root, nested-namespace, unstable,
  or non-user-space targets.
- It requires the PID-specific exact confirmation phrase.
- It executes one bounded command in a traced child, not in the original target.
- The original target is restored and detached before the command begins.
- The command has bounded runtime and output and inherits only a minimal
  environment.
- Cancellation and failure kill only the pidfd-identified injected child.
- Output artifacts are removed only after identity verification.
- Every mutation stage has unit-tested rollback behavior.
- Kind independently validates node-boundary mechanics and cleanup.
- An independent VM validates the outside-container host claim.
- Documentation states the residual tracer-crash risk and requires a disposable
  target.
- No reverse shell, persistence, arbitrary shellcode input, sysctl mutation,
  LSM bypass, seccomp suspension, credential rewriting, or destructive target
  replacement is introduced.

## Explicit exclusions

Do not include:

- an interactive shell or reverse shell;
- automatic target selection;
- PID 1 or kernel-thread tracing;
- support for multithreaded targets;
- `PTRACE_O_EXITKILL` on the original target;
- writes to `kernel.yama.ptrace_scope`;
- `PTRACE_O_SUSPEND_SECCOMP` or attempts to disable an LSM;
- a `setns`, mount, or chroot fallback;
- operator-supplied machine code or arbitrary remote syscalls;
- process credential/capability rewriting;
- a mode that exec-replaces or intentionally terminates the selected original
  process; or
- ARM, ARM64, 386, or other architecture implementations or test builds in the
  first release.

## Approved decisions and remaining validation

Implementation approval was received on 2026-09-09. The approved first-release
contract uses menu item `32`, runs one command, requires an explicitly selected
single-threaded disposable target and pidfds, keeps the 30-second and 1-MiB
defaults, and requires both Kind mechanics evidence and an independent-kernel VM
acceptance test. The Kind gate passed on 2026-09-09; the independent-kernel VM
gate remains outstanding.
