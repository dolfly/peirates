# Container escape expansion plan

Status: **IMPLEMENTED** for commands 25–27 and 29. Commands 25–27 were approved on 2026-09-04, and command 29 was separately authorized and completed on 2026-09-08 under the safety contract below. Command 29's dedicated automated positive test remains deferred until an independent-kernel VM harness is available. Command 28 remains detection-only.

The planning agent reviewed all 114 slides in the [Black Hat USA 2019 Compendium of Container Escapes](https://i.blackhat.com/USA-19/Thursday/us-19-Edwards-Compendium-Of-Container-Escapes-up.pdf) and inspected the existing `hostpid-breakout` implementation before producing this plan.

## Recommended initial scope

Add three commands:

| Menu | Command | Purpose |
|---:|---|---|
| 25 | `container-escape-scan` | Read-only assessment of available escape primitives |
| 26 | `docker-socket-breakout` | Enter the host controlled by an exposed Docker daemon |
| 27 | `hostroot-breakout` | Chroot into an already-mounted host filesystem |

The initial scope reserved two experimental commands as scan findings. Command
29 was subsequently authorized and implemented as described in the status
amendment above:

| Menu | Command | Status |
|---:|---|---|
| 28 | `cgroup-release-agent-breakout` | Detection-only; requires cgroup v1 and changes kernel-global configuration |
| 29 | `hostproc-core-pattern-breakout` | Implemented; temporarily overwrites and safely restores the host-wide crash-handler setting |

This prioritization follows the source slides:

- Slides 9–24: capabilities, namespaces, filesystems, cgroups, LSMs, and seccomp—inputs to the scanner.
- Slide 42: Docker-socket escape through privileged container creation.
- Slides 46–58: cgroup v1 `release_agent` and related usermode-helper mechanisms.
- Slides 60–64: writable host procfs and `core_pattern`.
- Slide 106: mounting the host root and entering it with `chroot`.
- Slides 31–40 and 66–105: runtime CVEs and kernel exploits that should not become general Peirates modules.

## Feature design

### 1. `container-escape-scan`

This must be strictly read-only and report prerequisites rather than claiming a vulnerability or guaranteed escape.

It should inspect:

- Effective UID and capabilities from `/proc/self/status`.
- PID, mount, user, network, IPC, UTS, and cgroup namespace identities.
- Container-root identity and possible host-root mounts.
- Docker-compatible Unix sockets:
  - `unix://` paths from `DOCKER_HOST`
  - `/var/run/docker.sock`
  - `/run/docker.sock`
  - an explicitly supplied socket
- Docker `_ping` and `/version` using bounded, read-only requests.
- Procfs mounts and whether `sys/kernel/core_pattern` appears writable.
- Cgroup version, available v1 controllers, `release_agent`, and `notify_on_release`.
- Overlay mount metadata and whether a host-visible `upperdir` can be determined.
- Likely blockers such as user namespaces, missing capabilities, read-only mounts, cgroup v2, LSMs, seccomp, or missing shells.

Each technique receives one result:

- `available`: all observable prerequisites are present.
- `candidate`: mutation would be required to prove it.
- `blocked`: a required prerequisite is absent.
- `unsupported`: the platform or runtime cannot support it.

The scan must not create containers, mount filesystems, change sysctls, launch payloads, enumerate environment variables, or expose sensitive image/container metadata.

### 2. `docker-socket-breakout`

Implement the Docker HTTP protocol directly over Unix sockets; do not depend on `docker`, `curl`, or `nsenter`.

Preflight:

1. Require Linux and an absolute Unix-socket path.
2. Reject symlinks and non-sockets.
3. Apply connection, response-size, and overall timeouts.
4. Verify `_ping` and API compatibility.
5. Select an already-present image that provides `/bin/sh` and `chroot`.
6. Explain that the daemon host may be a nested daemon or remote VM rather than the physical Kubernetes node.

Action:

1. Create a uniquely named and labeled container.
2. Configure it with:
   - `Privileged: true`
   - `PidMode: host`
   - `/:/host` read-write bind
   - open stdin and TTY
   - `chroot /host /bin/sh -i`
3. Start and attach to it.
4. Relay stdin, stdout, stderr, signals, and terminal resize events.
5. Restore terminal state on every return path.
6. On exit or interruption, verify the ownership label and remove only the exact created container ID.

The module must never pull an image automatically, leave a privileged container behind, create persistence, or claim that the physical host was reached without evidence.

Proposed aliases:

- `docker-breakout`
- `dockersock-breakout`

### 3. `hostroot-breakout`

This targets an existing host-root mount such as `/hostroot`.

Preflight:

1. Require Linux, effective UID 0, and `CAP_SYS_CHROOT`.
2. Accept an explicit absolute path; auto-select only when exactly one candidate exists.
3. Reject `/`, the current root, relative paths, symlinks, and non-directories.
4. Open the target with no-follow and close-on-exec protections.
5. Compare filesystem identity to prove it differs from the current root.
6. Require an executable `<target>/bin/sh`.

Action:

1. Re-exec Peirates into a private worker, following the current hostPID pattern.
2. Repeat the complete preflight in the worker.
3. Lock the OS thread and unshare filesystem attributes.
4. Use the already-open directory descriptor, `fchdir`, `chroot(".")`, and `chdir("/")`.
5. Launch `/bin/sh -i` with inherited streams and a minimal environment.
6. Exit the worker, returning the parent Peirates process unchanged.

This first implementation should remain filesystem-only. It must not automatically enter namespaces discovered beneath the mounted filesystem.

Proposed aliases:

- `host-root-breakout`
- `hostfs-breakout`

## Experimental techniques

### Cgroup v1 `release_agent`

Initially detection-only. Any future action requires a separate approval and:

- Confirmed cgroup v1 rather than unified cgroup v2.
- UID 0 and appropriate `CAP_SYS_ADMIN`.
- Writable `release_agent` and `notify_on_release`.
- A verified host-visible payload path.
- Exact operator confirmation.
- Snapshot, compare-and-restore, and ownership-aware cleanup.
- No reverse shell or persistence.

A successful positive test must run in a disposable VM with an independent kernel—not Kind, which shares the host kernel.

### Host-proc `core_pattern`

Initially detection-only, this action was separately authorized and completed
on 2026-09-08 with these mandatory constraints:

- Positively identified host procfs.
- A host-visible payload.
- Exact preservation of the original `core_pattern`.
- Refusal to replace an existing piped crash handler unless explicitly overridden.
- Compare-and-restore semantics.
- A disposable child as the only crashed process.
- An independent-kernel VM test harness.

The implementation does not add a reverse shell or persistence. A bounded,
explicitly authorized manual run from the existing Kind test pod succeeded on
2026-09-08: it reached a root shell in the kernel's initial namespaces and
independently verified restoration of the exact original `core_pattern` value.
No routine Kind integration target was added because `core_pattern` is
kernel-global. The dedicated automated positive test remains deferred to an
independent-kernel VM harness.

The implemented payload path uses the kernel's initial-namespace PID expansion:
`/bin/sh` reads the temporary handler through `/proc/%P/root`. This avoids an
unnecessary dependency on reading PID 1's root or deriving an overlay
`upperdir`; the random handler and both FIFOs remain tied to the disposable
crash worker's filesystem root. The private worker replaces itself with the
current container's `/bin/sh` before self-signalling with `SIGSEGV`, preventing
the Go runtime from turning the intended fatal signal into a normal exit.

## Explicit exclusions

Do not implement:

- CVE-2019-5736 and other historical Docker/runc or rkt lifecycle exploits.
- Dirty COW, vDSO manipulation, or other kernel-memory exploits.
- Kernel-module loading through `CAP_SYS_MODULE`.
- Raw device manipulation through `CAP_SYS_RAWIO`.
- `binfmt_misc`, `uevent_helper`, or `modprobe` until each receives a separate modern-kernel threat model and cleanup design.
- Containerd/CRI support under the Docker command name.
- A generic “try every escape” command.

These techniques are obsolete, architecture-sensitive, destructive, insufficiently specified by the deck, or capable of compromising the test host itself.

## Internal architecture

Keep everything under `internal/modules`:

```text
internal/modules/escapeutil
internal/modules/containerescape
internal/modules/dockersocket
internal/modules/hostroot
internal/modules/hostproc
```

Possible future packages:

```text
internal/modules/cgrouprelease
```

Shared `escapeutil` responsibilities:

- Capability parsing.
- Namespace and filesystem identity.
- `/proc/self/mountinfo` parsing.
- Safe path opening.
- Common finding/result types.

Each actionable module should separate read-only and mutating operations:

```go
Probe(...) (Finding, error)
Launch(...) error
```

`Launch` must repeat `Probe` immediately before mutation. The initial work should not refactor `internal/modules/hostpid`; shared helpers can be migrated later in a focused change.

Every module needs Linux implementation files and non-Linux stubs returning stable unsupported errors.

## Existing files to update

Application wiring:

- `internal/app/module_registry.go`
- `internal/app/dispatch.go`
- `internal/app/run.go`
- `internal/app/run_test.go`
- `internal/app/menu.go`
- `internal/app/module_commands_test.go`
- `internal/ui/menu.go`
- `internal/ui/completion.go`
- `internal/ui/completion_test.go`

Documentation:

- `docs/commands/container-escape-scan.md`
- `docs/commands/docker-socket-breakout.md`
- `docs/commands/hostroot-breakout.md`
- `docs/commands/hostproc-core-pattern-breakout.md`
- `docs/commands/README.md`
- `docs/commands/manifest.tsv`
- `test/README.md`

Integration:

- `test/container-escape-scan-kind-integration.sh`
- `test/docker-socket-breakout-kind-integration.sh`
- `test/hostroot-breakout-kind-integration.sh`
- `Makefile`
- `.github/workflows/kind.yaml`
- Kind aggregate and cluster-ownership tests

The existing root `plan.txt` is historical and must not be overwritten.

## Test strategy

Unit tests must cover:

- Capability, namespace, mountinfo, and escaped-path parsing.
- Proof that scanner probes never call mutating operations.
- Malformed proc files, symlinks, short reads, timeouts, and oversized Docker responses.
- Docker request bodies, streaming, signals, TTY restoration, ownership labels, cleanup ordering, and refusal to pull images.
- Host-root qualification, descriptor cleanup, worker routing, syscall order, inherited streams, and shell exit status.
- Non-Linux behavior.
- Numeric, canonical, and alias dispatch.
- Menu, completion, and documentation-manifest parity.

Disposable Kind tests:

- `hostroot-breakout`: mount the Kind node’s `/` at `/hostroot`, create a marker through independent `docker exec`, then prove access through the shell.
- `docker-socket-breakout`: use a nested Docker-in-Docker daemon and expose only its socket. Never mount the workstation or CI host Docker socket.
- `container-escape-scan`: compare findings against independently observed fixture state.
- Include negative controls for absent mounts, missing capabilities, permission-denied sockets, Docker API errors, and unusable images.
- Prove every Peirates-created container and Kind cluster is absent afterward.

## Implementation phases

1. Approve the safety contract, command names, menu numbers, aliases, and exclusions.
2. Add `escapeutil` and the read-only scanner with unit and Kind coverage.
3. Add `hostroot-breakout` with a private worker and Kind coverage.
4. Add `docker-socket-breakout` with its bounded API client and nested-Docker coverage.
5. Run the release gate:
   - formatting, unit tests, race tests, and vet;
   - static default build;
   - static distribution builds for AMD64, ARM, ARM64, and 386;
   - documentation and shell checks;
   - Kind inventory, cleanup, and live integration tests.
6. Separately review whether to build a VM harness for the two kernel-global experimental techniques.

## Acceptance criteria

- Existing commands, aliases, flags, kubectl routing, paths, and build artifacts remain compatible.
- Scanning performs no writes or process launches.
- Every action repeats preflight and fails closed on ambiguity.
- No reverse shell, cron entry, setuid file, kernel module, persistence, or automatic image pull is introduced.
- The parent Peirates process retains its root, namespaces, terminal state, and environment.
- Docker resources are uniquely labeled and deleted by exact ID.
- Host-root breakout leaves no persistent resources.
- Failures report missing prerequisites without claiming successful escape.
- Static Linux builds remain valid for AMD64, ARM, ARM64, and 386.
- Live tests use independent external-state assertions and prove cleanup.

## Validation commands

```sh
git diff --check
go fmt ./...
go test ./internal/modules/... ./internal/app ./internal/ui
go test -race ./internal/modules/... ./internal/app ./internal/ui
go vet ./...
make test-quiet
make build
file peirates
ldd peirates
make dist DIST_OUTPUT_DIR=/tmp/peirates-dist-check DIST_COMPRESS=no
bash -n test/*kind-integration.sh test/run-kind-tests.sh
make kind-cluster-ownership-test
make kind-aggregate-test
make container-escape-scan-kind-test
make hostroot-breakout-kind-test
make docker-socket-breakout-kind-test
kind get clusters
```

For `ldd`, the expected result is “not a dynamic executable” or equivalent. Inspect every uncompressed distribution binary with `file` or `readelf` before removing the temporary output.

## Security warnings

- A Docker socket is root-equivalent access to the daemon’s host.
- A mounted host root allows arbitrary host-file modification even without host namespace entry.
- “Privileged” is not a portable guarantee; user namespaces, LSMs, seccomp, runtime policy, and nested daemons change the result.
- `release_agent` and `core_pattern` alter kernel-global state and can execute outside the Kind node boundary.
- A shell reached through a nested daemon is the daemon host, not necessarily the Kubernetes node or physical system.
- Tests must never mount a developer or CI host Docker socket, host procfs, or cgroup control files into an exploit fixture.

## Approved decisions

1. Implement only commands 25–27 initially.
2. Keep item 28 detection-only. Item 29 was separately approved and implemented
   on 2026-09-08; defer its dedicated automated positive test until an
   independent-kernel VM harness exists.
3. Keep `hostroot-breakout` filesystem-only.
4. Require a pre-existing Docker image and prohibit automatic pulls.
5. Use existing stdin prompting conventions in direct `-m` mode rather than adding global flags.
6. Require a separate approval before any kernel-global escape action.
7. Persist this approved plan as `docs/plans/container-escapes.md`.
