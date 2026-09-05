#!/usr/bin/env bash
# This live Kind integration test verifies that Peirates can enter an existing
# mount of a disposable Kind node root without entering any host namespaces.
#
# It tests:
# - numeric, canonical, and alias dispatch through a real static Peirates binary
# - explicit host-root selection, node-root identity, and read-only marker access
# - return from the interactive host-root shell after an explicit exit
# - fail-closed behavior without CAP_SYS_CHROOT or a distinct host-root mount
# - operation without Kubernetes API credentials or RBAC inside the runner pods

# Stop immediately on setup, command, pipeline, or unset-variable failures.
set -euo pipefail

# Resolve shared helpers and define the isolated cluster and fixture names.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"
cluster_name="${PEIRATES_HOSTROOT_BREAKOUT_KIND_CLUSTER:-peirates-hostroot-breakout-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-hostroot-breakout-test"
privileged_pod="peirates-hostroot-privileged"
missing_capability_pod="peirates-hostroot-missing-capability"
absent_mount_pod="peirates-hostroot-absent-mount"
marker_path="/peirates-hostroot-disposable-marker"
marker_value="peirates-hostroot-node-root"
kubeconfig_file=""
config_file=""
peirates_binary=""
cluster_claim=""
cluster_ownership=none

# Delete only the proven-owned cluster and this run's temporary files.
cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${peirates_binary}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-hostroot-breakout-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-hostroot-breakout-binary.XXXXXX)"

# Verify required tools, serialize this cluster name, and fail closed if it exists.
for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create one disposable node without mounting any physical-host path into it.
cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

# Create the namespace before Docker-side fixture setup so ownership regression
# tests have a deterministic post-create command to observe.
kubectl --context "${context}" create namespace "${namespace}"

# Place a harmless marker only in the disposable Kind node and independently
# record the node filesystem-root identity before any Peirates process runs.
docker exec "${node_name}" sh -c "printf '%s\n' '${marker_value}' > '${marker_path}'"
node_root_identity="$(docker exec "${node_name}" stat -c '%d:%i' /)"
if [[ "$(docker exec "${node_name}" cat "${marker_path}")" != "${marker_value}" ]]; then
    echo "failed to create the disposable node-root marker" >&2
    exit 1
fi

# Create one qualifying pod and two negative controls. The two pods that mount
# hostPath / receive only the disposable Kind node container's root; the Kind
# configuration above never exposes a physical Docker-host path to the node.
# Every host-root volume is read-only and no pod receives a service-account token.
kubectl --context "${context}" -n "${namespace}" apply -f - <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${privileged_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: node-root
      mountPath: /hostroot
      readOnly: true
  volumes:
  - name: node-root
    hostPath:
      path: /
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${missing_capability_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: node-root
      mountPath: /hostroot
      readOnly: true
  volumes:
  - name: node-root
    hostPath:
      path: /
      type: Directory
---
apiVersion: v1
kind: Pod
metadata:
  name: ${absent_mount_pod}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
PODS
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready pod --all --timeout=120s

# Build one CGO-disabled static binary for the node architecture and install it
# in all pods through the operator's kubeconfig, not an in-pod credential.
build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
for pod in "${privileged_pod}" "${missing_capability_pod}" "${absent_mount_pod}"; do
    kubectl --context "${context}" -n "${namespace}" cp \
        "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- chmod 0755 /tmp/peirates
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- \
        test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
done

# Establish from outside Peirates that the mounted node root is distinct from
# the ordinary container root and has the exact identity observed through Docker.
runner_root_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${privileged_pod}" -- stat -c '%d:%i' /)"
mounted_root_identity="$(kubectl --context "${context}" -n "${namespace}" exec \
    "${privileged_pod}" -- stat -c '%d:%i' /hostroot)"
if [[ "${runner_root_identity}" == "${node_root_identity}" ]]; then
    echo "positive runner root unexpectedly matches the disposable node root" >&2
    exit 1
fi
if [[ "${mounted_root_identity}" != "${node_root_identity}" ]]; then
    echo "mounted host root does not match the disposable node root" >&2
    printf 'node=%s mounted=%s\n' "${node_root_identity}" "${mounted_root_identity}" >&2
    exit 1
fi
if kubectl --context "${context}" -n "${namespace}" exec "${privileged_pod}" -- \
    test -e "${marker_path}" >/dev/null 2>&1; then
    echo "node marker was visible at the container root before breakout" >&2
    exit 1
fi
if kubectl --context "${context}" -n "${namespace}" exec "${absent_mount_pod}" -- \
    test -e /hostroot >/dev/null 2>&1; then
    echo "absent-mount control unexpectedly contains /hostroot" >&2
    exit 1
fi

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "host-root breakout ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

# Run a dispatch form, select /hostroot, issue only read-only shell commands,
# and compare the results with state observed independently through Docker.
run_positive_case() {
    local module="$1" output
    if ! output="$({
        printf '%s\n' \
            '/hostroot' \
            'printf "HOSTROOT_UID=%s\n" "$(id -u)"' \
            'printf "HOSTROOT_PWD=%s\n" "$(pwd)"' \
            "printf 'HOSTROOT_MARKER=%s\\n' \"\$(cat '${marker_path}')\"" \
            'printf "HOSTROOT_IDENTITY=%s\n" "$(stat -c '\''%d:%i'\'' /)"' \
            'exit'
    } | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${privileged_pod}" -- \
        /tmp/peirates -c -m "${module}" 2>&1)"; then
        echo "host-root breakout failed for ${module}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi

    assert_contains "${output}" "Attempting menu option ${module}" "${module} dispatch"
    assert_contains "${output}" "Mounted host-root path [auto-detect]:" "${module} target prompt"
    assert_contains "${output}" \
        "Entering mounted host root /hostroot; exit returns to Peirates." "${module} boundary"
    assert_contains "${output}" "HOSTROOT_UID=0" "${module} UID"
    assert_contains "${output}" "HOSTROOT_PWD=/" "${module} working directory"
    assert_contains "${output}" "HOSTROOT_MARKER=${marker_value}" "${module} node marker"
    assert_contains "${output}" "HOSTROOT_IDENTITY=${node_root_identity}" "${module} node-root identity"
}

# Exercise the numbered item, canonical command, and one named alias.
for module in 27 hostroot-breakout host-root-breakout; do
    run_positive_case "${module}"
done

# Root without CAP_SYS_CHROOT must fail before launching a private worker even
# though the disposable node root is mounted and readable.
if ! missing_capability_output="$({
    printf '%s\n' '/hostroot'
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i \
    "${missing_capability_pod}" -- /tmp/peirates -c -m hostroot-breakout 2>&1)"; then
    echo "missing-capability negative control exited unexpectedly" >&2
    printf '%s\n' "${missing_capability_output}" >&2
    exit 1
fi
assert_contains "${missing_capability_output}" \
    "required effective capability is missing: CAP_SYS_CHROOT" "missing-capability control"
if [[ "${missing_capability_output}" == *"Entering mounted host root"* ||
    "${missing_capability_output}" == *"${marker_value}"* ]]; then
    echo "missing-capability control reached the host-root worker" >&2
    printf '%s\n' "${missing_capability_output}" >&2
    exit 1
fi

# A privileged pod with no host-root volume must find no automatic candidate.
if ! absent_mount_output="$({
    printf '\n'
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i \
    "${absent_mount_pod}" -- /tmp/peirates -c -m hostfs-breakout 2>&1)"; then
    echo "absent-mount negative control exited unexpectedly" >&2
    printf '%s\n' "${absent_mount_output}" >&2
    exit 1
fi
assert_contains "${absent_mount_output}" \
    "no mounted host-root candidate was found" "absent-mount control"
if [[ "${absent_mount_output}" == *"Entering mounted host root"* ||
    "${absent_mount_output}" == *"${marker_value}"* ]]; then
    echo "absent-mount control reached the host-root worker" >&2
    printf '%s\n' "${absent_mount_output}" >&2
    exit 1
fi

# The ordinary container root is never accepted as a substitute for a distinct
# mounted host root, even in the privileged negative-control pod.
if ! current_root_output="$({
    printf '%s\n' '/'
} | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i \
    "${absent_mount_pod}" -- /tmp/peirates -c -m hostroot-breakout 2>&1)"; then
    echo "current-root negative control exited unexpectedly" >&2
    printf '%s\n' "${current_root_output}" >&2
    exit 1
fi
assert_contains "${current_root_output}" \
    "target path must not be the current root" "current-root control"
if [[ "${current_root_output}" == *"Entering mounted host root"* ]]; then
    echo "current-root control reached the host-root worker" >&2
    printf '%s\n' "${current_root_output}" >&2
    exit 1
fi

# Verify from Docker that the read-only positive cases left the disposable node
# marker unchanged, then report success for menu item 27.
if [[ "$(docker exec "${node_name}" cat "${marker_path}")" != "${marker_value}" ]]; then
    echo "disposable node-root marker changed during read-only breakout checks" >&2
    exit 1
fi
echo "main-menu item 27 passed live mounted host-root breakout integration testing"
