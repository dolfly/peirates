# Docker socket host shell

## Menu entry

- **Menu item:** `26`
- **Canonical command:** `docker-socket-breakout`
- **Aliases:** `docker-breakout`, `dockersock-breakout`
- **Maturity:** Alpha on Linux when all prerequisites are satisfied

## Purpose

Use an explicitly exposed Docker-compatible Unix socket to create a temporary
privileged container, bind the Docker daemon host's root filesystem, and attach
the current terminal to an interactive host-root `/bin/sh`.

Access to a writable Docker socket is effectively administrative access to the
daemon host. This is the exposed-socket technique described on slide 42 of the
[Black Hat USA 2019 Compendium of Container Escapes](https://i.blackhat.com/USA-19/Thursday/us-19-Edwards-Compendium-Of-Container-Escapes-up.pdf).
Use it only against a daemon and host for which this level of access is
explicitly authorized.

## Prerequisites and authorization

Peirates must:

- run on Linux;
- be able to connect to an absolute Docker Unix-socket path;
- receive a direct socket path rather than a symbolic link;
- have permission to call the Docker API through that socket;
- reach a Docker-compatible API version new enough for the required container
  options;
- select an image already present in that daemon; and
- select an image whose `/bin/sh` can run and whose `PATH` contains `chroot`.

The daemon must permit a privileged container with host PID mode and a
read-write bind of `/`. Peirates neither pulls an image nor accepts a registry
reference that exists only remotely. Before asking for an image, it lists the
tagged images already reported by the selected daemon. The operator must enter
one exact local tag or image reference from that daemon.

No Kubernetes API access, service-account token, RBAC permission, external
`docker` command, or external `curl` command is required by the module.

The socket determines the target. It may belong to a nested Docker-in-Docker
daemon, a socket proxy, or another daemon environment rather than the
Kubernetes node or physical machine. Treat the returned daemon information and
the shell's own observations as evidence of the target actually reached.

## Usage

Select any supported command form from the full menu:

```text
26
docker-socket-breakout
docker-breakout
dockersock-breakout
```

Peirates first prompts for the socket. An empty line selects
`/var/run/docker.sock`. It then reports the daemon and tagged local images and
prompts for the exact image reference:

```text
Docker socket path [/var/run/docker.sock]:
Existing image reference (must contain /bin/sh and chroot):
```

One-shot module mode still reads both choices and then shell input from
standard input. For example:

```sh
printf '%s\n' \
  '/var/run/docker.sock' \
  'authorized-local-image:tag' \
  'id' \
  'pwd' \
  'exit' | peirates -c -m docker-socket-breakout
```

Use `exit` or end the shell input to leave the host shell. In direct module
mode, Peirates then exits normally. The command does not ask for an additional
confirmation after the socket and image have been supplied.

## What it does

Peirates performs the following sequence:

1. It rejects a relative, unclean, non-socket, or final-component symlink path.
   It holds a descriptor for the resolved parent directory and verifies the
   socket's device and inode around every connection so a replaced socket is
   not silently trusted.
2. It sends bounded, timeout-controlled `GET /_ping` and `GET /version`
   requests. For the first prompt it requests only the daemon's tagged local
   image summaries.
3. After image selection, it repeats the socket and daemon checks and inspects
   that exact image reference. It never calls Docker's image-create or pull
   endpoint.
4. It creates a constrained, network-disabled validation container using the
   selected image. That container has a read-only root, drops every capability,
   enables `no-new-privileges`, overrides the image user with UID/GID 0, and
   runs only a `/bin/sh` check for `chroot`. Peirates waits for it and removes
   it by exact ID.
5. It creates a second uniquely named and labeled container with a TTY, open
   stdin, UID/GID 0, `Privileged: true`, `PidMode: host`, and `/:/host:rw`.
6. With a real terminal, the new container executes
   `chroot /host /bin/sh -i` in Docker TTY mode. Peirates forwards terminal
   resize events and restores local terminal settings on every return path.
   With scripted, non-terminal input it executes `chroot /host /bin/sh`
   without a TTY, sets `TERM=dumb`, and decodes Docker's bounded stream-frame
   headers. Both modes attach through Docker's hijacked HTTP stream; a real
   terminal keeps its caller-supplied `TERM` value.
7. After the shell exits—or if startup, attachment, input, or signal handling
   fails—Peirates inspects the exact container ID and verifies its ownership
   label before force-removing it.

Both temporary containers carry the label
`com.inguardians.peirates.docker-socket-breakout`. Cleanup refuses to remove a
container whose label value no longer matches the current run. If creation has
an ambiguous response, Peirates resolves only its unique generated name,
verifies the same label, and removes the resulting exact ID. Ordinary cleanup
also verifies that inspection returns the exact recorded container ID before
removing anything.

## Expected output

Successful setup identifies the daemon and explicitly warns about its target
boundary. Immediately before shell output, Peirates prints:

```text
Entering the Docker daemon host filesystem; exit returns to Peirates.
```

Commands such as `id`, `pwd`, filesystem marker checks, and namespace links
under `/proc/self/ns` can help establish what the shell reached. Because the
container uses a Docker TTY, its standard error is combined with standard
output while attached.

The message confirms attachment to a shell rooted at the selected daemon's
view of `/`; it does not prove that the daemon host is a Kubernetes node or the
physical system.

## Side effects and cleanup

The module creates one short-lived constrained image-check container and, only
after that check succeeds, one privileged shell container. It does not pull an
image, create a Kubernetes resource, install persistence, modify cron, or make
a reverse connection. Both containers are intended to be removed before the
module returns.

**Warning:** commands entered in the attached shell run as root against the
daemon host filesystem and host PID namespace. They can expose credentials,
alter or destroy host data, terminate host processes, disrupt workloads, or
install persistence. Peirates cannot clean up changes made by the operator
inside that shell.

If the daemon becomes unavailable, ownership inspection fails, or the label is
changed, Peirates fails closed rather than deleting an unverified container.
In that case, an authorized operator must inspect the named daemon and remove
only containers carrying the matching Peirates ownership label.

## Failure modes

- Non-Linux execution reports that the function is unsupported.
- A missing, relative, unclean, non-socket, or symbolic-link socket path is
  rejected before an API request.
- Permission errors, connection timeouts, malformed responses, oversized
  responses, an incompatible API version, and socket replacement abort the
  attempt.
- A remote-only or misspelled image reference fails exact image inspection;
  Peirates reports that no pull was attempted.
- An image without a usable `/bin/sh` and `chroot` fails in the constrained
  validation container before the privileged container is created.
- Daemon policy may reject privileged mode, host PID mode, the root bind, TTY
  attachment, or `chroot` execution.
- The daemon host may lack `/bin/sh` even when the selected container image
  provides it.
- An attach interruption force-removes the owned privileged container rather
  than leaving it running. Input supplied through a custom non-file reader
  should be finite or cancelable; ordinary terminal input uses cancellable
  polling.
- A nonzero host-shell exit is returned as an error after cleanup.
- Cleanup errors are reported, and a label mismatch prevents automatic
  deletion.

## Implementation and tests

- [Docker socket module](../../internal/modules/dockersocket)
- [Application prompting and stream handoff](../../internal/app/container_escape_modules.go)
- [Application registration](../../internal/app/module_registry.go)
- [Unit tests with a fake Unix-socket Docker daemon](../../internal/modules/dockersocket/dockersocket_linux_test.go)
- [Disposable nested-Docker Kind integration test](../../test/docker-socket-breakout-kind-integration.sh)
