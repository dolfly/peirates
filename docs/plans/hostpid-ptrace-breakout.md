# HostPID ptrace breakout plan

Status: **INTERACTIVE SHELL IMPLEMENTED — INDEPENDENT-KERNEL VM VALIDATION
PENDING.** The original single-command implementation and its Kind mechanics
test passed on 2026-09-09. The operator subsequently approved replacing that
bounded command with a PTY-backed interactive shell. On 2026-09-09, the new
shell passed both the Linux AMD64 test against a test-owned disposable process
and the full disposable Kind mechanics test, including both dispatch forms,
namespace evidence, target preservation, negative controls, and cleanup. The
interactive design below supersedes the original command-capture, timeout, and
output-file design. On 2026-09-09, the Kind mechanics test passed again after
the runner dropped every default capability and added back only
`CAP_SYS_PTRACE`. Do not claim an outside-all-containers breakout until the
independent-kernel VM gate passes.

## Goal

Add an experimental Peirates command that opens an interactive shell in the
namespaces, credentials, and filesystem context of an explicitly selected root
process visible from a `hostPID: true` container. The intended Kubernetes
container is root, shares the node PID namespace, and has `SYS_PTRACE` in its
container capability list. `SYS_ADMIN` is not required.

The canonical command is `hostpid-ptrace-breakout`, assigned to menu item `32`
with no aliases.

## Interactive-shell amendment

The current interface launches `/bin/sh -i` attached to a PTY allocated
through the selected process's root. Peirates relays its local terminal to the
PTY until the shell exits. This replaces the originally approved `/bin/sh -c`
runner and removes its capture file, 30-second command timeout, 1-MiB output
limit, and command prompt.

The interactive change does not relax the security model:

- the operator still selects an eligible disposable process explicitly;
- the exact PID-specific confirmation is still required before mutation;
- the original process is restored and detached before the shell starts;
- only the injected child receives `PTRACE_O_EXITKILL`;
- cancellation kills only the pidfd-identified child; and
- the physical-host claim still requires an independent-kernel VM test.

An interactive shell is intentionally long-lived and can perform arbitrary
authorized actions. There is no runtime or output bound after confirmation.
The warning and exact confirmation are therefore part of the safety contract,
not optional presentation.

## Terminology and capability contract

The Linux capability is `CAP_SYS_PTRACE`. Kubernetes manifests omit the
`CAP_` prefix:

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
```

`CAP_SYS_PTRACE` authorizes tracing arbitrary processes and protected procfs
access. The engine does not require `CAP_SYS_ADMIN` and does not use `setns`,
mount, or chroot behavior. Capabilities are evaluated relative to user
namespaces; `CAP_SYS_PTRACE` held only in a nested user namespace is
insufficient.

Primary references:

- [Linux `ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux namespace handles](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Linux PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [Linux Yama ptrace policy](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [Kubernetes capability syntax](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

## Security model and hard limitation

`ptrace` temporarily stops a live thread and permits Peirates to replace its
registers and instruction bytes. Ordinary success and handled failures can
restore that state, but the operation cannot be transactional. A tracer
`SIGKILL`, runtime crash, kernel failure, container termination, or node loss
during the patched interval can corrupt, stop, or terminate the target.

Therefore:

- candidates are called **eligible**, never **safe**;
- PID 1 is always prohibited;
- Peirates, its ancestors, kernel threads, already traced tasks,
  multithreaded processes, non-root processes, and nested PID-namespace
  processes are prohibited;
- only a deliberately disposable, single-threaded process created for the
  operation may be selected; and
- the implementation must never replace or intentionally terminate the
  original process as a fallback.

## Boundary definition

The implementation cannot prove from procfs that a process is outside every
possible container. "Visible PID 1's boundary" means the target matches the
visible PID 1 in every namespace and root identity Peirates compares. On Kind,
that boundary is normally the Kind node container rather than the physical
machine.

Before listing a candidate, compare it with visible PID 1 for:

- PID, user, mount, UTS, IPC, network, cgroup, and optional time namespaces;
- filesystem-root device and inode identity; and
- PID namespace depth.

The current process and visible PID 1 must share PID and user namespaces.
Peirates must also be effective UID 0 with `CAP_SYS_PTRACE`. Yama
`ptrace_scope=3` is a hard failure; other seccomp and LSM restrictions are
reported as warnings and may reject the actual attach.

## Candidate eligibility

Enumerate numeric procfs PIDs without opening arbitrary paths derived from
process-controlled text. Record PID, start time, `comm`, executable identity,
sanitized command line and digest, state, UIDs, thread count, tracer PID,
core-dumping state, namespace identities, root identity, and PID depth.

A candidate must:

- be PID greater than 1 and not Peirates or one of its ancestors;
- be effective root, single-threaded, running or sleeping, and not traced or
  core-dumping;
- match visible PID 1's observable namespace and root boundary;
- expose executable `/bin/sh` and a usable `/dev/ptmx` through its root; and
- have a stable start time and pidfd identity.

No target is auto-selected, even when exactly one qualifies. Sensitive command
lines remain truncated and sanitized in the UI.

## Operator interaction

The application flow is:

1. Print capability, boundary, and irreversible-crash caveats.
2. List eligible targets by PID, `comm`, executable, and bounded command line.
3. Prompt `Disposable host PID to trace: `.
4. Re-probe and require the exact selected candidate to remain eligible.
5. Require `TRACE-DISPOSABLE-HOST-PROCESS-<pid>` exactly.
6. Print the status line before mutation:

   ```text
   [hostpid-ptrace-breakout] tracing disposable host PID 1234 to open an interactive shell in visible PID 1's namespaces
   ```

7. Put a local terminal into raw mode, if present, and relay it to the host
   PTY. Preserve input already buffered while reading the confirmation.
8. Propagate the initial terminal dimensions and `SIGWINCH` updates.
9. On `exit`, EOF, cancellation, or shell termination, restore the local
   terminal and report shell status plus target restoration/detach evidence.

EOF or incorrect confirmation cancels without attaching. Direct module mode
uses the same prompts. Non-terminal input is treated as bounded scripted shell
input and receives a trailing EOF character after all input is relayed.

## Parent, PTY, and worker architecture

The normal Peirates process owns prompts, terminal state, input/output relay,
signals, and final reporting. A private re-exec owns ptrace and wait operations.
It is dispatched before ordinary application initialization and locks its OS
thread before the first ptrace call.

Before starting the worker, the parent:

1. opens `/proc/<pid>/root` and verifies its recorded device/inode identity;
2. opens `dev/ptmx` descriptor-relative through that root;
3. unlocks the PTY and obtains its slave number;
4. verifies `dev/pts/<number>` is a character device;
5. records the slave's device, inode, and device ID; and
6. retains the nonblocking PTY master for relay and lifecycle ownership.

The worker request contains only the selected candidate evidence and PTY
identity. It is length-framed over an inherited anonymous pipe, never argv or
environment. Shell keystrokes and output pass through the PTY, not the worker
protocol. The worker verifies the target and PTY identity again before attach
and returns structured result and cleanup information over a second pipe.

## AMD64 ptrace engine

### Attach and snapshot

1. Open a pidfd for the target and repeat every eligibility check.
2. Use `PTRACE_SEIZE`, then `PTRACE_INTERRUPT`; do not use `PTRACE_ATTACH`.
3. Wait for the exact expected stop and preserve a pending external signal for
   later reinjection.
4. Save the complete general-purpose register set.
5. Verify the instruction pointer lies in a private executable mapping.
6. Save and verify every full machine word that will be patched.
7. Enable fork/clone tracing on the original, but never
   `PTRACE_O_EXITKILL`.

### Remote syscall primitive

Use a fixed AMD64 `syscall`/trap sequence at the stopped instruction pointer.
Set registers according to the x86-64 ABI, continue only the stopped thread,
wait for the exact trap, and decode negative returns as errno values. Allow
only fixed internal syscalls. Never accept operator machine code or syscall
numbers. Verify all scratch-memory writes by reading them back.

### Disposable child

Clone without `CLONE_VM` or `CLONE_THREAD`, using `CLONE_PARENT|SIGCHLD` so the
original target is not responsible for reaping the child. Accept only the PID
reported by the ptrace event, immediately open its pidfd, and apply
`PTRACE_O_EXITKILL`, exec tracing, and exit tracing to the child only.

Before the child performs shell setup:

1. verify its namespaces and root still match the selected target;
2. unmap scratch memory from the original;
3. restore and verify the original instruction bytes and registers; and
4. detach the original with any preserved signal.

### Interactive shell setup

Using only fixed remote syscalls and verified scratch data, the child:

1. sets a descriptive process name;
2. changes directory to `/`;
3. calls `setsid`;
4. opens `/dev/pts/<number>`;
5. uses `TIOCSCTTY` to make it the controlling terminal;
6. duplicates it onto file descriptors 0, 1, and 2; and
7. executes `/bin/sh -i` with only `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`,
   and `PATH`.

Successful exec must be observed as `PTRACE_EVENT_EXEC`. Continue and reap the
shell's real exit or signal. On cancellation or relay failure, signal the
worker, kill only the exact child through its pidfd, continue it if stopped,
and reap it. Never signal the original target during child cleanup.

## Cleanup state machine

Mutation stages are monotonic:

```text
qualified
  -> target-seized
  -> target-stopped
  -> target-patched
  -> child-created
  -> child-contained
  -> target-restored
  -> target-detached
  -> child-execed
  -> child-reaped
```

Cleanup order is:

1. stop or kill only the pidfd-identified injected child when needed;
2. restore the original instruction bytes and registers while stopped;
3. verify the restoration;
4. detach the original and reinject a preserved signal;
5. reap ptrace events and close pidfds; and
6. close the PTY master, which releases the transient slave.

Restoration or detach failure takes precedence over a successful shell result.
Signal handlers initiate the same cleanup path. Unrecoverable crash and node
failure risk remains explicitly documented.

## File and package layout

Implementation ownership remains internal:

- `internal/modules/hostpidptrace`: probe, protocol, PTY relay, AMD64 engine,
  unsupported-platform behavior, and tests;
- `internal/app/hostpid_ptrace.go`: prompts, raw terminal lifecycle, and
  reporting;
- `internal/app/run.go`: private worker routing;
- `internal/app/menu.go` and `internal/ui/menu.go`: menu text and dispatch;
- `internal/modules/containerescape`: read-only prerequisite detection;
- `docs/commands/hostpid-ptrace-breakout.md`: operator documentation; and
- `test/hostpid-ptrace-breakout-kind-integration.sh`: disposable Kind
  mechanics test.

Lower-level packages must not import `internal/app`, and no public package API
is added.

## Test plan

Unit and local tests cover:

- capability, namespace, procfs, candidate, and exact-confirmation logic;
- protocol framing and PTY identity validation;
- AMD64 register/syscall construction and errno decoding;
- ptrace event handling and every cleanup stage through fault injection;
- preservation of the original target before child exec; and
- a real interactive `/bin/sh -i` driven through a PTY against only a
  Peirates-test-owned disposable process when local ptrace policy permits it.

The disposable Linux AMD64 Kind test must:

1. claim and create a uniquely named cluster with fail-closed cleanup;
2. build only the static AMD64 binary;
3. create a uniquely marked, bounded root `sleep` in the Kind node;
4. record its PID, start time, executable, command line, and namespaces from
   Docker;
5. run a non-privileged `hostPID: true` pod with all default capabilities
   dropped, only `SYS_PTRACE` added, and runtime-default seccomp;
6. drive the interactive shell with a random marker command and `exit` through
   both numeric and canonical dispatch;
7. independently compare UID, hostname, working directory, and namespace
   output with the Kind node;
8. verify the original target retains its identity and remains alive;
9. verify no injected interactive shell remains; and
10. remove only test-owned fixtures and prove cluster cleanup.

Negative controls cover missing capabilities, private PID namespace, nested
user namespace where supported, a non-boundary target, multithreaded target,
PID 1, wrong confirmation, and target exit between selection and attach.

Kind proves mechanics only. The outside-all-containers acceptance gate uses a
disposable VM with Kubernetes installed directly on its independent kernel and
a sacrificial root process created from the VM console. It must independently
verify namespace identity, interactive shell output, target survival, child
cleanup, and fixture removal. Never use a production node or existing service.

## Validation commands

Run serially and never cross-compile non-AMD64 variants:

```sh
gofmt -w <changed-go-files>
go test ./internal/modules/hostpidptrace ./internal/app ./internal/modules/containerescape
GOFLAGS=-p=1 make hostpid-ptrace-breakout-kind-test
GOFLAGS=-p=1 make test-quiet
make build
file peirates
ldd peirates
git diff --check
```

## Acceptance criteria

- Linux AMD64 only; static AMD64 build succeeds.
- Effective UID 0, `CAP_SYS_PTRACE`, hostPID visibility, and a compatible user
  namespace are required; `CAP_SYS_ADMIN` is not required.
- PID 1 and unsafe target classes are rejected; no target is auto-selected.
- Exact PID-specific confirmation is required.
- A verified target-root PTY backs `/bin/sh -i`.
- The original target is restored and detached before shell setup begins.
- Local terminal raw mode and window size are restored/propagated correctly.
- Cancellation kills only the pidfd-identified child.
- Mutation rollback and PTY relay behavior have focused tests.
- Kind independently validates node-boundary mechanics and cleanup.
- An independent VM remains required for the physical-host claim.
- No reverse-shell callback, persistence, arbitrary shellcode, sysctl mutation,
  LSM bypass, seccomp suspension, credential rewriting, destructive target
  replacement, or non-AMD64 build is introduced.

## Explicit exclusions

- reverse-shell or listener behavior;
- automatic target selection;
- PID 1, kernel-thread, or multithreaded-target tracing;
- `PTRACE_O_EXITKILL` on the original target;
- Yama, seccomp, or LSM policy modification;
- a `setns`, mount, or chroot fallback;
- operator-supplied machine code or arbitrary remote syscalls;
- credential or capability rewriting;
- replacement or intentional termination of the selected original process;
  and
- ARM, ARM64, 386, or other architecture implementations or test builds.
