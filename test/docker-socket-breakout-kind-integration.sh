#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can use only a nested
# Docker-in-Docker Unix socket to enter that daemon container's root filesystem.
# The fixture never exposes the outer Docker socket or any physical-host path.
#
# It tests:
# - numeric, canonical, and alias dispatch through a real static Peirates binary
# - exact selection of a locally imported image with /bin/sh and chroot
# - daemon-root marker, root identity, and PID namespace evidence checked
#   independently through the Docker-in-Docker sidecar
# - removal of every Peirates-labeled nested container after each invocation
# - fail-closed handling for an absent socket, a missing image/API response, and
#   a local image that lacks chroot
# - operation without a Kubernetes service-account token or RBAC permissions

# Stop immediately on setup, command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define the isolated cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_DOCKER_SOCKET_BREAKOUT_KIND_CLUSTER:-peirates-docker-socket-breakout-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-docker-socket-breakout-test"
pod_name="peirates-nested-docker"
dind_image="${PEIRATES_DOCKER_SOCKET_DIND_IMAGE:-docker:27.5.1-dind}"
socket_path="/var/run/docker.sock"
usable_image="peirates-breakout-fixture:local"
unusable_image="peirates-no-chroot-fixture:local"
missing_image="peirates-missing-fixture:never"
ownership_label="com.inguardians.peirates.docker-socket-breakout"
marker_path="/peirates-docker-daemon-marker"
marker_value="peirates-nested-docker-daemon-root"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only the proven-owned cluster and this run's temporary local files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-docker-socket-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-docker-socket-binary.XXXXXX)"

# Verify tools, serialize this exact cluster name, and refuse existing state.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create one Kind node without adding host mounts to the node configuration.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

# Create an isolated namespace and a two-container pod. Only an emptyDir socket
# directory is shared: neither the outer Docker socket nor a hostPath is mounted.
kubectl --context "${context}" create namespace "${namespace}"
kubectl --context "${context}" -n "${namespace}" apply -f - <<POD
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
  - name: daemon
    image: ${dind_image}
    imagePullPolicy: IfNotPresent
    command: ["dockerd"]
    args:
    - "--host=unix://${socket_path}"
    - "--storage-driver=vfs"
    - "--group=0"
    env:
    - name: DOCKER_HOST
      value: "unix://${socket_path}"
    - name: DOCKER_TLS_CERTDIR
      value: ""
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: nested-docker-run
      mountPath: /var/run
  - name: client
    image: ${dind_image}
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: nested-docker-run
      mountPath: /var/run
  volumes:
  - name: nested-docker-run
    emptyDir: {}
POD
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${pod_name}" --timeout=180s

# Wait for the nested daemon API rather than treating Pod readiness as daemon
# readiness. The selected image is built locally only after this succeeds.
daemon_ready=false
for _ in {1..120}; do
    if kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
        docker -H "unix://${socket_path}" info >/dev/null 2>&1; then
        daemon_ready=true
        break
    fi
    sleep 1
done
if [[ "${daemon_ready}" != true ]]; then
    echo "nested Docker daemon did not become ready" >&2
    kubectl --context "${context}" -n "${namespace}" logs "${pod_name}" -c daemon >&2 || true
    exit 1
fi

# Import a tiny root filesystem directly into the nested daemon. This performs
# no nested registry pull: both images are assembled from the already-running,
# version-pinned DinD container's BusyBox and runtime libraries.
build_nested_image() {
    local image="$1"
    local include_chroot="$2"

    kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
        env PEIRATES_FIXTURE_IMAGE="${image}" PEIRATES_INCLUDE_CHROOT="${include_chroot}" \
        sh -ceu '
            rootfs="$(mktemp -d /tmp/peirates-rootfs.XXXXXX)"
            trap '\''rm -rf -- "${rootfs}"'\'' EXIT
            mkdir -p "${rootfs}/bin"
            cp /bin/busybox "${rootfs}/bin/busybox"
            if [ -d /lib ]; then
                cp -a /lib "${rootfs}/lib"
            fi
            ln -s busybox "${rootfs}/bin/sh"
            if [ "${PEIRATES_INCLUDE_CHROOT}" = true ]; then
                ln -s busybox "${rootfs}/bin/chroot"
            fi
			tar -C "${rootfs}" -cf - . |
				docker -H unix:///var/run/docker.sock image import --change "USER 65534" - "${PEIRATES_FIXTURE_IMAGE}" >/dev/null
        '
}
build_nested_image "${usable_image}" true
build_nested_image "${unusable_image}" false

# Build one static binary for the Kind node architecture and copy it only into
# the unprivileged socket client container.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
kubectl --context "${context}" -n "${namespace}" cp -c client \
    "${peirates_binary}" "${pod_name}:/tmp/peirates"
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c client -- \
    chmod 0755 /tmp/peirates

# Establish independent fixture evidence in the nested daemon container and
# prove it is absent from the ordinary client root before any breakout.
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
    sh -c "printf '%s\\n' '${marker_value}' > '${marker_path}'"
daemon_root_identity="$(kubectl --context "${context}" -n "${namespace}" \
    exec "${pod_name}" -c daemon -- stat -c '%d:%i' /)"
daemon_pid_namespace="$(kubectl --context "${context}" -n "${namespace}" \
    exec "${pod_name}" -c daemon -- readlink /proc/1/ns/pid)"
if kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c client -- \
    test -e "${marker_path}" >/dev/null 2>&1; then
    echo "nested daemon marker was visible in the client before breakout" >&2
    exit 1
fi
kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c client -- \
    test -S "${socket_path}"
for container in daemon client; do
    if kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c "${container}" -- \
        test -e /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; then
        echo "service-account token unexpectedly mounted in ${container}" >&2
        exit 1
    fi
done

# Shared assertions check command output and exact nested-container cleanup.
assert_contains() {
    local output="$1"
    local expected="$2"
    local scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "Docker socket breakout ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

assert_no_owned_containers() {
    local scenario="$1"
    local remaining

    remaining="$(kubectl --context "${context}" -n "${namespace}" \
        exec "${pod_name}" -c daemon -- docker -H "unix://${socket_path}" ps -aq \
        --filter "label=${ownership_label}")"
    if [[ -n "${remaining}" ]]; then
        echo "Peirates-labeled nested containers remain after ${scenario}: ${remaining}" >&2
        kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
            docker -H "unix://${socket_path}" ps -a --no-trunc \
            --filter "label=${ownership_label}" >&2 || true
        exit 1
    fi
}

# Run one public dispatch form, execute only read-only checks in the returned
# shell, and compare its evidence to the DinD sidecar observations above.
run_positive_case() {
    local module="$1"
    local output

    if ! output="$({
        printf '%s\n' \
            "${socket_path}" \
            "${usable_image}" \
            'printf "DOCKERSOCK_UID=%s\n" "$(id -u)"' \
            'printf "DOCKERSOCK_PWD=%s\n" "$(pwd)"' \
            "printf 'DOCKERSOCK_MARKER=%s\\n' \"\$(cat '${marker_path}')\"" \
            'printf "DOCKERSOCK_ROOT=%s\n" "$(stat -c '\''%d:%i'\'' /)"' \
            'printf "DOCKERSOCK_PID=%s\n" "$(readlink /proc/1/ns/pid)"' \
            'exit'
    } | timeout 120s kubectl --context "${context}" -n "${namespace}" exec -i \
        "${pod_name}" -c client -- /tmp/peirates -c -m "${module}" 2>&1)"; then
        echo "Docker socket breakout failed for ${module}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi

    assert_contains "${output}" "Attempting menu option ${module}" "${module} dispatch"
    assert_contains "${output}" "Existing tagged images:" "${module} image discovery"
    assert_contains "${output}" "${usable_image}" "${module} local image"
    assert_contains "${output}" "may be nested or remote" "${module} target caveat"
    assert_contains "${output}" \
        "Entering the Docker daemon host filesystem; exit returns to Peirates." \
        "${module} shell boundary"
    assert_contains "${output}" "DOCKERSOCK_UID=0" "${module} UID"
    assert_contains "${output}" "DOCKERSOCK_PWD=/" "${module} working directory"
    assert_contains "${output}" "DOCKERSOCK_MARKER=${marker_value}" "${module} daemon marker"
    assert_contains "${output}" "DOCKERSOCK_ROOT=${daemon_root_identity}" "${module} daemon root"
    assert_contains "${output}" "DOCKERSOCK_PID=${daemon_pid_namespace}" "${module} daemon PID namespace"
    assert_no_owned_containers "${module}"
}

# Record the local nested image inventory before invoking Peirates. Comparing
# this complete list after all cases independently proves that no path pulled
# or otherwise introduced an image.
images_before="$(kubectl --context "${context}" -n "${namespace}" \
    exec "${pod_name}" -c daemon -- docker -H "unix://${socket_path}" image ls \
    --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' | LC_ALL=C sort)"
if kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
    docker -H "unix://${socket_path}" image inspect "${missing_image}" >/dev/null 2>&1; then
    echo "missing-image negative control unexpectedly exists before testing" >&2
    exit 1
fi

# Exercise the numbered item, canonical command, and one named alias.
for module in 26 docker-socket-breakout docker-breakout; do
    run_positive_case "${module}"
done

# A nonexistent socket must fail before image selection or container creation.
absent_socket="/var/run/peirates-absent-docker.sock"
if ! absent_output="$(printf '%s\n' "${absent_socket}" | timeout 90s \
    kubectl --context "${context}" -n "${namespace}" exec -i "${pod_name}" -c client -- \
    /tmp/peirates -c -m docker-socket-breakout 2>&1)"; then
    echo "absent-socket control exited unexpectedly" >&2
    printf '%s\n' "${absent_output}" >&2
    exit 1
fi
assert_contains "${absent_output}" "inspect Docker socket" "absent-socket control"
if [[ "${absent_output}" == *"Entering the Docker daemon host filesystem"* ]]; then
    echo "absent-socket control reached a host shell" >&2
    exit 1
fi
assert_no_owned_containers "absent-socket control"

# A reference missing from the nested daemon exercises its Docker API error and
# must not trigger an image pull or create either temporary container.
if ! missing_output="$({
    printf '%s\n' "${socket_path}" "${missing_image}"
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i \
    "${pod_name}" -c client -- /tmp/peirates -c -m dockersock-breakout 2>&1)"; then
    echo "missing-image control exited unexpectedly" >&2
    printf '%s\n' "${missing_output}" >&2
    exit 1
fi
assert_contains "${missing_output}" "inspect already-present image" "missing-image API control"
assert_contains "${missing_output}" "no pull was attempted" "missing-image no-pull control"
if [[ "${missing_output}" == *"Entering the Docker daemon host filesystem"* ]]; then
    echo "missing-image control reached a host shell" >&2
    exit 1
fi
assert_no_owned_containers "missing-image control"
if kubectl --context "${context}" -n "${namespace}" exec "${pod_name}" -c daemon -- \
    docker -H "unix://${socket_path}" image inspect "${missing_image}" >/dev/null 2>&1; then
    echo "missing image appeared after Peirates; an unexpected pull may have occurred" >&2
    exit 1
fi

# An already-present image without a chroot command must be rejected by the
# constrained validation container, which must itself be removed.
if ! unusable_output="$({
    printf '%s\n' "${socket_path}" "${unusable_image}"
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i \
    "${pod_name}" -c client -- /tmp/peirates -c -m docker-socket-breakout 2>&1)"; then
    echo "unusable-image control exited unexpectedly" >&2
    printf '%s\n' "${unusable_output}" >&2
    exit 1
fi
assert_contains "${unusable_output}" \
    "does not provide usable /bin/sh and chroot" "unusable-image control"
if [[ "${unusable_output}" == *"Entering the Docker daemon host filesystem"* ||
    "${unusable_output}" == *"${marker_value}"* ]]; then
    echo "unusable-image control reached the daemon host shell" >&2
    exit 1
fi
assert_no_owned_containers "unusable-image control"

# Prove the complete nested image inventory is unchanged by every invocation.
images_after="$(kubectl --context "${context}" -n "${namespace}" \
    exec "${pod_name}" -c daemon -- docker -H "unix://${socket_path}" image ls \
    --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' | LC_ALL=C sort)"
if [[ "${images_after}" != "${images_before}" ]]; then
    echo "nested Docker image inventory changed during breakout testing" >&2
    printf 'before:\n%s\nafter:\n%s\n' "${images_before}" "${images_after}" >&2
    exit 1
fi

# Report completion only after positive evidence, negative controls, exact
# container cleanup, no-pull evidence, and cluster cleanup registration pass.
echo "main-menu item 26 passed nested Docker socket breakout integration testing"
