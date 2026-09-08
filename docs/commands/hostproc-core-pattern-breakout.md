# Host-proc core-pattern shell

## Menu entry

- **Menu item:** `29`
- **Canonical command:** `hostproc-core-pattern-breakout`
- **Aliases:** None
- **Maturity:** Experimental on Linux; changes a kernel-wide setting

## Purpose

Enter the initial namespaces of the current kernel through a writable host
procfs mount. Peirates temporarily installs a piped Linux core-dump handler,
crashes one disposable child process, and relays an interactive `/bin/sh`
started by the handler. The handler runs with root credentials in the initial
namespaces, as described by the Linux
[`core(5)` manual](https://man7.org/linux/man-pages/man5/core.5.html).

The initial namespaces belong to the kernel host. They may be outside a
containerized Kubernetes node such as Kind, or inside the virtual machine that
provides the kernel. Use this command only on a disposable system or a host
where changing the kernel-wide crash-handler configuration is explicitly
authorized.

## Prerequisites and authorization

Peirates requires all of the following:

- Linux and effective UID 0;
- a full procfs mount;
- direct read-write access to that procfs mount's
  `sys/kernel/core_pattern` file;
- a writable current filesystem root for a randomly named temporary directory;
- `/bin/sh` in the current container for the disposable crash worker; and
- `/bin/sh` available in the kernel's initial mount namespace when the handler
  is invoked.

The procfs mount must be an absolute, normalized path with no symbolic-link
components. Auto-detection proceeds only when exactly one writable
`core_pattern` file identity is visible. Peirates does not require access to
PID 1's root or an overlay `upperdir`. These checks establish access to the
kernel-wide setting; they do not establish which physical machine owns the
kernel.

## Usage

Select the command from the full interactive menu:

```text
29
hostproc-core-pattern-breakout
```

Peirates first prompts for the procfs mount:

```text
Host procfs mount [auto-detect]: /hostproc
```

Press Enter to auto-detect a unique qualifying mount. After a read-only probe,
Peirates displays the selected path, the current `core_pattern`, and the
initial-namespace caveat.

For a normal file-style `core_pattern`, Peirates requires this exact phrase:

```text
OVERWRITE-HOST-CORE-PATTERN
```

If the existing value already begins with `|`, the host has a piped crash
handler. Peirates refuses to replace it unless the operator instead types the
stronger exact override:

```text
REPLACE-PIPED-CORE-HANDLER
```

Any other input, including end-of-file, cancels without changing the host.
Direct module invocation uses the same two prompts and confirmation:

```sh
printf '/hostproc\nOVERWRITE-HOST-CORE-PATTERN\n' | peirates -c -m hostproc-core-pattern-breakout
```

For an interactive shell, keep standard input attached to a terminal. Run
`exit` in the resulting shell to return to Peirates.

## What it does

The first probe is read-only. After exact confirmation, the launch path repeats
the complete probe and compares the current value and file identity with what
the operator reviewed. Peirates refuses the mutation if either changed.

Peirates creates a randomly named, mode-`0700` directory in the current
container root. It places a short handler and two named pipes in that directory
and verifies their contents and types without following final symlinks. It then
constructs a bounded pattern of this form:

```text
|/bin/sh /proc/%P/root/.p<random-token>/h
```

Linux expands `%P` to the disposable worker's PID in the initial PID namespace.
The initial-namespace `/bin/sh` therefore opens the handler through that live
worker's root. This makes the payload reachable without reading PID 1's root,
depending on an overlay backing path, or copying the Peirates binary.

Peirates opens and retains the qualified `core_pattern` file, compares its
value again, and installs a temporary `|handler` value. It then re-executes its
own binary as a private worker. That worker enables core dumping, replaces
itself with the current container's `/bin/sh`, and has that disposable shell
send `SIGSEGV` only to itself. Replacing the Go process ensures the language
runtime cannot convert the fatal signal into an ordinary exit before the
kernel invokes the configured core handler. No existing application process
is selected or crashed.

The host core handler emits a unique readiness marker and starts
`/bin/sh -i` with a minimal environment over the two named pipes. Once the
marker is verified, Peirates compare-restores the exact original
`core_pattern` and verifies it before relaying any shell input. If another
actor changes the setting after installation, Peirates refuses to overwrite
that external value and reports the cleanup failure.

## Expected output

A successful launch includes status similar to:

```text
[hostproc-core-pattern-breakout] temporarily replacing /hostproc/sys/kernel/core_pattern to start a shell in the initial namespaces; the original value will be restored before shell relay
Host core_pattern restored. Entering the initial-namespace shell through /hostproc; exit returns to Peirates.
```

The shell prompt is normally `[peirates-hostproc]#`. Independently verify the
boundary reached before making changes.

## Side effects and cleanup

During the short trigger window, `core_pattern` is changed for every process
sharing the kernel. An unrelated crash in that window could invoke the
temporary handler. Existing crash collection may also be interrupted,
especially when the stronger piped-handler override is used.

On success, interruption, or ordinary failure, Peirates attempts to:

1. restore the original value only if the setting still matches its temporary
   handler;
2. verify the restored value;
3. terminate an uncollected disposable worker; and
4. close the named pipes and remove its randomly named temporary directory.

The command does not add a cron job, reverse shell, setuid file, service, or
other persistence. Commands entered in the resulting shell can still modify
or destroy host state and are the operator's responsibility.

## Failure modes

- Non-Linux execution reports the command as unsupported.
- Non-root execution, a non-procfs path, a partial procfs mount, symlinked path,
  or read-only `core_pattern` fails during the read-only probe.
- No qualifying candidate or multiple distinct candidates causes
  auto-detection to fail closed.
- A read-only current root prevents temporary handler and FIFO creation.
- A missing initial-namespace `/bin/sh`, an unavailable initial `/proc`, or
  policy preventing `/proc/%P/root` traversal prevents handler startup; the
  bounded timeout then invokes restoration and cleanup.
- Unsafe or overlong temporary patterns are rejected before mutation.
- A changed `core_pattern` value or file identity aborts the operation.
- An existing piped crash handler requires the stronger confirmation phrase.
- Failure to observe the unique readiness marker stops the attempt and invokes
  guarded restoration and cleanup.
- A value changed externally after Peirates installs its handler is preserved
  rather than overwritten; manual inspection and cleanup are then required.
- Seccomp, an LSM, user namespaces, runtime policy, or core-dump policy may
  prevent the disposable child or handler from running.

## Implementation and validation

- [Host-proc capability](../../internal/modules/hostproc)
- [Application prompt and launch wiring](../../internal/app/hostproc_core_pattern.go)
- [Application registration](../../internal/app/module_registry.go)
- [Private crash-worker routing](../../internal/app/run.go)
- [Container escape implementation plan](../plans/container-escapes.md)
- [Linux kernel `core_pattern` documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html#core-pattern)

No dedicated unit or integration test is included yet, per the implementation
request. In particular, this breakout must never be positively exercised in a
Kind cluster because Kind shares its kernel with the machine running the
cluster. Validation is limited to formatting, compilation, static builds, and
the repository's existing non-breakout tests until an independent-kernel,
disposable VM harness is separately added.
