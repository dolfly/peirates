# Mounted host-root shell

## Menu entry

- **Menu item:** `27`
- **Canonical command:** `hostroot-breakout`
- **Aliases:** `host-root-breakout`, `hostfs-breakout`
- **Maturity:** Stable on Linux when all prerequisites are satisfied

## Purpose

Change an isolated Peirates worker's filesystem root to an already-mounted host
root and open an interactive `/bin/sh`. This is useful when an authorized
operator finds a container that can see the node filesystem through a mount
such as `/hostroot` and has the privilege needed to call `chroot`.

The command provides complete interactive access to the selected filesystem.
It does not enter the host PID, mount, network, IPC, UTS, user, cgroup, or time
namespaces. Use it only against a disposable node or a host where that level of
filesystem access is explicitly authorized.

## Prerequisites and authorization

The Peirates process must:

- run on Linux with effective UID 0;
- hold effective `CAP_SYS_CHROOT`;
- have an existing host-root mount at an absolute path other than `/`;
- see a target filesystem root whose device and inode differ from its current
  container root; and
- be able to execute `/bin/sh` inside that target root.

The target path must be normalized and no path component may be a symbolic
link. Peirates opens the target one component at a time with no-follow
semantics and retains the worker's final descriptor across its root transition.

No Kubernetes API access, RBAC permission, service-account token, `kubectl`,
or external `chroot` binary is required. Peirates validates local process and
filesystem state; the operator remains responsible for confirming that the
mount belongs to the intended host.

## Usage

Select the function from the full interactive menu with any supported form:

```text
27
hostroot-breakout
host-root-breakout
hostfs-breakout
```

Peirates then prompts for the mounted root:

```text
Mounted host-root path [auto-detect]: /hostroot
```

Press Enter without a path to use auto-detection. Auto-detection reads
`/proc/self/mountinfo` and proceeds only when exactly one outermost,
non-pseudo-filesystem mount rooted at `/` passes every qualification check.
Qualified recursive child mounts beneath that root are not counted as separate
roots. It fails closed if no candidate or multiple independent candidates are
visible.

Direct module invocation is also supported, but still reads the path from
standard input:

```sh
printf '/hostroot\n' | peirates -c -m hostroot-breakout
```

For an interactive shell, run Peirates from a terminal, enter the path at the
prompt, and then enter shell commands normally. Run `exit` in the host-root
shell to return to Peirates; in direct module mode, Peirates then terminates
normally.

## What it does

Peirates validates the effective UID, `CAP_SYS_CHROOT`, target path, filesystem
identity, directory descriptor, and target shell. It then closes the preflight
descriptor and starts an isolated copy of its own executable with the selected
path and its expected device/inode identity as private worker arguments.

The worker repeats the complete preflight immediately before changing its
filesystem view and refuses to continue unless the newly opened directory has
the exact device/inode identity approved by the parent. It locks itself to one
operating-system thread, separates its filesystem attributes with
`unshare(CLONE_FS)`, changes directory through the already-open target
descriptor, calls `chroot(".")`, and changes directory to the new `/`. It does
not call `setns` or attempt to discover or enter any host namespace.

Finally, the worker runs `/bin/sh -i` with inherited standard input, output,
and error streams. It supplies only a minimal host-oriented environment:
`HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `PS1`, and, when present, `TERM`.
Container variables such as service-account settings, `LD_*`, `ENV`, and
`BASH_ENV` are not inherited by the shell.

## Expected output

For an explicit `/hostroot` target, Peirates prints:

```text
Entering mounted host root /hostroot; exit returns to Peirates.
```

The prompt is normally `[peirates-hostroot]#`. Prompt rendering depends on the
target's `/bin/sh`. Commands such as `id`, `pwd`, and `stat /` can be used to
independently confirm the resulting identity and filesystem root.

## Side effects and cleanup

Peirates does not create a Pod, mount a filesystem, write a host file, or leave
a background process. Filesystem-root changes apply only to the isolated
worker. Exiting the shell terminates that worker and discards its process-local
root and filesystem state.

**Warning:** commands entered in the shell execute with the worker's
privileges against the selected filesystem. Those commands can modify or
destroy host data, expose credentials, or establish persistence. Any
operator-created changes require explicit cleanup.

## Failure modes

- Non-Linux execution reports that the function is unsupported.
- Non-root execution or a missing effective `CAP_SYS_CHROOT` fails before a
  worker starts.
- Relative, unnormalized, root, any-component symbolic-link, missing, and non-directory
  targets are rejected.
- A target whose device/inode identity changes between parent and worker
  preflight is rejected before any filesystem mutation.
- A target matching the current container root is rejected because it does not
  provide a distinct filesystem to enter.
- A missing, non-regular, or non-executable target `/bin/sh` prevents entry.
- Linux kernels without the `openat2` system call fail safely while validating
  the target shell rather than falling back to path-based resolution.
- Blank input fails when mountinfo contains no host-root candidate or more than
  one candidate; supply one explicit absolute path to resolve ambiguity.
- Seccomp, AppArmor, SELinux, another LSM, or a container runtime may reject an
  otherwise valid `unshare` or `chroot` operation.
- Failure after `chroot` terminates only the isolated worker; the parent
  Peirates process retains its original filesystem root.
- A nonzero host-shell exit is reported as an isolated-worker failure before
  control returns to Peirates.

## Implementation and tests

- [Host-root capability](../../internal/modules/hostroot)
- [Application registration](../../internal/app/module_registry.go)
- [Prompt and launch wiring](../../internal/app/container_escape_modules.go)
- [Private worker routing](../../internal/app/run.go)
- [Unit tests](../../internal/modules/hostroot/hostroot_linux_test.go)
- [Disposable Kind integration test](../../test/hostroot-breakout-kind-integration.sh)
