#!/usr/bin/env bash
# Validate hostPID ptrace mechanics only against disposable processes created
# and owned by this test inside a disposable Kind node container.
#
# Tested behavior:
# - Linux AMD64 static build and numeric/canonical command routing
# - one bounded command at visible PID 1's Kind-node boundary
# - byte-for-byte target identity survival and pidfd child cleanup
# - missing capabilities, private PID, non-boundary, multithreaded, PID 1,
#   wrong-confirmation, target-exit, and command-timeout controls
#
# Kind cannot establish an outside-all-containers physical-host claim. This
# script never traces an existing service or changes Yama, seccomp, or LSM
# policy.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
run_kind_script_with_signal_forwarding "${BASH_SOURCE[0]}" "$@"

cluster_name="${PEIRATES_HOSTPID_PTRACE_KIND_CLUSTER:-peirates-hostpid-ptrace-integration}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="peirates-hostpid-ptrace-test"
runner="ptrace-runner"
no_ptrace="ptrace-no-sys-ptrace"
no_admin="ptrace-no-sys-admin"
private_pid="ptrace-private-pid"
nested_target="ptrace-nested-target"
marker="peirates-ptrace-$RANDOM-$RANDOM"
target_pid=""
target_start=""
multithread_pid=""
multithread_pidfile=""
short_pid=""
kubeconfig_file=""
config_file=""
peirates_binary=""
thread_source=""
thread_binary=""
thread_node_binary="/usr/local/bin/peirates-ptrace-thread-target"
race_fifo=""
race_output=""
race_process=""
cluster_claim=""
cluster_ownership=none

kill_owned_node_process() {
    local pid="$1" expected_start="$2" expected_marker="$3"
    [[ -n "${pid}" && -n "${expected_start}" ]] || return 0
    if ! docker inspect "${node_name}" >/dev/null 2>&1; then
        return 0
    fi
    local current_start current_command
    current_start="$(docker exec "${node_name}" sh -c \
        'test -r "/proc/$1/stat" && awk "{print \$22}" "/proc/$1/stat"' sh "${pid}" 2>/dev/null || true)"
    current_command="$(docker exec "${node_name}" sh -c \
        'test -r "/proc/$1/cmdline" && tr "\000" " " < "/proc/$1/cmdline"' sh "${pid}" 2>/dev/null || true)"
    if [[ "${current_start}" == "${expected_start}" && "${current_command}" == *"${expected_marker}"* ]]; then
        docker exec "${node_name}" sh -c 'kill "$1" 2>/dev/null || true' sh "${pid}" >/dev/null
    fi
}

cleanup() {
    local status="$?"
    if [[ -n "${race_process}" ]] && kill -0 "${race_process}" 2>/dev/null; then
        kill "${race_process}" 2>/dev/null || true
        wait "${race_process}" 2>/dev/null || true
    fi
    kill_owned_node_process "${short_pid}" "${short_start:-}" "${short_marker:-}"
    kill_owned_node_process "${multithread_pid}" "${multithread_start:-}" "${multithread_marker:-}"
    kill_owned_node_process "${target_pid}" "${target_start}" "${marker}"
    if [[ -n "${multithread_pidfile}" ]] && docker inspect "${node_name}" >/dev/null 2>&1; then
        docker exec "${node_name}" rm -f "${multithread_pidfile}" >/dev/null 2>&1 || true
        docker exec "${node_name}" rm -f "${thread_node_binary}" >/dev/null 2>&1 || true
    fi
    finish_kind_script_cleanup "${status}" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${peirates_binary}" "${thread_source}" \
        "${thread_binary}" "${race_fifo}" "${race_output}" "${kubeconfig_file}"
}
install_kind_script_traps cleanup

for required in kind kubectl docker go timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-hostpid-ptrace-kind.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-hostpid-ptrace-binary.XXXXXX)"
thread_source="$(mktemp /tmp/peirates-ptrace-thread-target.XXXXXX.go)"
thread_binary="$(mktemp /tmp/peirates-ptrace-thread-target.XXXXXX)"

acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

# Create one unmounted Kind node; the test is intentionally bounded to that
# node container rather than the physical Docker host.
printf '%s\n' \
    'kind: Cluster' \
    'apiVersion: kind.x-k8s.io/v1alpha4' \
    'nodes:' \
    '- role: control-plane' >"${config_file}"
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

kubectl --context "${context}" create namespace "${namespace}"

[[ "$(docker exec "${node_name}" uname -m)" == "x86_64" ]] || {
    echo "hostpid-ptrace integration requires an AMD64 Kind node" >&2
    exit 1
}

# Compile Peirates and the deliberately multithreaded negative fixture for
# Linux AMD64 only, serially to avoid overloading the test machine.
GOCACHE="${GOCACHE:-/tmp/peirates-go-build}" \
GOMODCACHE="${GOMODCACHE:-/tmp/peirates-go-mod}" \
GOFLAGS=-p=1 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -tags netgo,osusergo -ldflags '-extldflags "-static"' \
    -o "${peirates_binary}" "${root_dir}/cmd/peirates"

printf '%s\n' \
    'package main' \
    'import ("os"; "runtime"; "time")' \
    'func main() { runtime.LockOSThread(); go func(){ for { runtime.Gosched() } }(); _ = os.Args; time.Sleep(10*time.Minute) }' \
    >"${thread_source}"
GOCACHE="${GOCACHE:-/tmp/peirates-go-build}" GOFLAGS=-p=1 \
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${thread_binary}" "${thread_source}"

docker exec -i "${node_name}" /bin/bash -c \
    'umask 022; cat > "$1"; chmod 0755 "$1"' _ "${thread_node_binary}" \
    <"${thread_binary}"
docker exec "${node_name}" test -x "${thread_node_binary}"

# Start and record the only process the positive case may trace. Its argv[0]
# carries a unique marker, and cleanup rechecks start time plus that marker
# before signalling the PID.
target_pid="$(docker exec "${node_name}" /bin/bash -c \
    'nohup /bin/bash -c '\''exec -a "$1" /bin/sleep 600'\'' _ "$1" >/dev/null 2>&1 & echo $!' \
    _ "${marker}")"
target_start="$(docker exec "${node_name}" awk '{print $22}' "/proc/${target_pid}/stat")"
target_executable="$(docker exec "${node_name}" readlink "/proc/${target_pid}/exe")"
target_command="$(docker exec "${node_name}" sh -c 'tr "\000" " " < "/proc/$1/cmdline"' sh "${target_pid}")"
[[ "${target_command}" == *"${marker}"* ]]

node_hostname="$(docker exec "${node_name}" hostname)"
node_pid_ns="$(docker exec "${node_name}" readlink /proc/1/ns/pid)"
node_mount_ns="$(docker exec "${node_name}" readlink /proc/1/ns/mnt)"
node_uts_ns="$(docker exec "${node_name}" readlink /proc/1/ns/uts)"

# The target-in-a-container negative fixture has a private root and namespace
# boundary even though its PID is visible to the hostPID runner.
kubectl --context "${context}" -n "${namespace}" apply -f - <<PODS
apiVersion: v1
kind: Pod
metadata:
  name: ${runner}
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities:
        add: ["SYS_PTRACE", "SYS_ADMIN"]
      seccompProfile:
        type: RuntimeDefault
---
apiVersion: v1
kind: Pod
metadata:
  name: ${no_ptrace}
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      capabilities:
        add: ["SYS_ADMIN"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${no_admin}
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      capabilities:
        add: ["SYS_PTRACE"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${private_pid}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      capabilities:
        add: ["SYS_PTRACE", "SYS_ADMIN"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${nested_target}
spec:
  automountServiceAccountToken: false
  containers:
  - name: test
    image: busybox:1.36.1
    command: ["sh", "-c", "exec sleep 4242"]
    securityContext:
      runAsUser: 0
PODS
kubectl --context "${context}" -n "${namespace}" wait --for=condition=Ready pod --all --timeout=120s

for pod in "${runner}" "${no_ptrace}" "${no_admin}" "${private_pid}"; do
    kubectl --context "${context}" -n "${namespace}" cp "${peirates_binary}" "${pod}:/tmp/peirates"
    kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- chmod 0755 /tmp/peirates
done

assert_contains() {
    local output="$1" expected="$2" scenario="$3"
    if [[ "${output}" != *"${expected}"* ]]; then
        echo "hostPID ptrace ${scenario} output did not contain: ${expected}" >&2
        printf '%s\n' "${output}" >&2
        exit 1
    fi
}

run_positive() {
    local module="$1" command output
    command="printf 'PTRACE_MARKER=%s\\n' '${marker}'; printf 'PTRACE_UID=%s\\n' \"\$(id -u)\"; printf 'PTRACE_HOST=%s\\n' \"\$(hostname)\"; printf 'PTRACE_PWD=%s\\n' \"\$(pwd)\"; printf 'PTRACE_PIDNS=%s\\n' \"\$(readlink /proc/self/ns/pid)\"; printf 'PTRACE_MNTNS=%s\\n' \"\$(readlink /proc/self/ns/mnt)\"; printf 'PTRACE_UTSNS=%s\\n' \"\$(readlink /proc/self/ns/uts)\""
    output="$({
        printf '%s\n' "${target_pid}" "${command}" \
            "TRACE-DISPOSABLE-HOST-PROCESS-${target_pid}"
    } | timeout 90s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
        /tmp/peirates -c -m "${module}" 2>&1)"
    assert_contains "${output}" "PTRACE_MARKER=${marker}" "${module} marker"
    assert_contains "${output}" "PTRACE_UID=0" "${module} UID"
    assert_contains "${output}" "PTRACE_HOST=${node_hostname}" "${module} hostname"
    assert_contains "${output}" "PTRACE_PWD=/" "${module} working directory"
    assert_contains "${output}" "PTRACE_PIDNS=${node_pid_ns}" "${module} PID namespace"
    assert_contains "${output}" "PTRACE_MNTNS=${node_mount_ns}" "${module} mount namespace"
    assert_contains "${output}" "PTRACE_UTSNS=${node_uts_ns}" "${module} UTS namespace"
    assert_contains "${output}" "restored=true detached=true" "${module} restoration"
    assert_contains "${output}" "output artifact removed=true" "${module} output cleanup"
}

# Exercise both supported dispatch forms; the first release intentionally has
# no aliases.
run_positive 32
run_positive hostpid-ptrace-breakout

# Independently prove the original disposable process retained its identity.
[[ "$(docker exec "${node_name}" awk '{print $22}' "/proc/${target_pid}/stat")" == "${target_start}" ]]
[[ "$(docker exec "${node_name}" readlink "/proc/${target_pid}/exe")" == "${target_executable}" ]]
[[ "$(docker exec "${node_name}" sh -c 'tr "\000" " " < "/proc/$1/cmdline"' sh "${target_pid}")" == "${target_command}" ]]

# Capability and private-PID controls must fail during read-only preflight.
for record in \
    "${no_ptrace}:CAP_SYS_PTRACE" \
    "${no_admin}:CAP_SYS_ADMIN" \
    "${private_pid}:no eligible disposable host process"; do
    IFS=: read -r pod expected <<<"${record}"
    output="$(timeout 60s kubectl --context "${context}" -n "${namespace}" exec "${pod}" -- \
        /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
    assert_contains "${output}" "${expected}" "${pod} negative control"
done

# PID 1 and a private-container target are visible but never eligible. PID 1 is
# rejected before candidate lookup, while the nested process fails lookup.
nested_pid="$(kubectl --context "${context}" -n "${namespace}" exec "${runner}" -- sh -c \
    'for path in /proc/[0-9]*/cmdline; do command=$(tr "\000" " " < "$path" 2>/dev/null || true); case "$command" in *"sleep 4242"*) basename "$(dirname "$path")"; break;; esac; done')"
output="$({ printf '%s\n' 1; } | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
assert_contains "${output}" "disposable PID greater than 1 is required" "rejected PID 1"
output="$({ printf '%s\n' "${nested_pid}"; } | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
assert_contains "${output}" "not in the eligible target list" "nested target PID ${nested_pid}"

# A test-owned Go process supplies the multithreaded negative target.
multithread_marker="peirates-multithread-${RANDOM}"
multithread_pidfile="/tmp/${multithread_marker}.pid"
docker exec -d "${node_name}" /bin/bash -c \
    'echo $$ > "$1"; exec -a "$2" "$3" "$2"' \
    _ "${multithread_pidfile}" "${multithread_marker}" "${thread_node_binary}"
for _ in {1..100}; do
    if docker exec "${node_name}" test -s "${multithread_pidfile}"; then
        multithread_pid="$(docker exec "${node_name}" cat "${multithread_pidfile}")"
        docker exec "${node_name}" test -r "/proc/${multithread_pid}/stat" && break
    fi
    sleep 0.05
done
[[ -n "${multithread_pid}" ]]
multithread_start="$(docker exec "${node_name}" awk '{print $22}' "/proc/${multithread_pid}/stat")"
output="$({ printf '%s\n' "${multithread_pid}"; } | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
assert_contains "${output}" "not in the eligible target list" "multithreaded target"

# Wrong confirmation never attaches and leaves the target identity unchanged.
output="$({ printf '%s\n' "${target_pid}" id WRONG; } | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
assert_contains "${output}" "breakout cancelled; no process was traced" "wrong confirmation"
[[ "$(docker exec "${node_name}" awk '{print $22}' "/proc/${target_pid}/stat")" == "${target_start}" ]]

# Race control: wait for the first listing, select a live short-lived target,
# wait for command input (which proves the second app-level probe passed), then
# let the target exit before confirmation. The private worker must reject it.
short_marker="peirates-short-${RANDOM}"
short_pid="$(docker exec "${node_name}" /bin/bash -c \
    'nohup /bin/bash -c '\''exec -a "$1" /bin/sleep 30'\'' _ "$1" >/dev/null 2>&1 & echo $!' _ "${short_marker}")"
short_start="$(docker exec "${node_name}" awk '{print $22}' "/proc/${short_pid}/stat")"
race_fifo="$(mktemp /tmp/peirates-ptrace-race-input.XXXXXX)"
race_output="$(mktemp /tmp/peirates-ptrace-race-output.XXXXXX)"
rm "${race_fifo}"
mkfifo -m 600 "${race_fifo}"
timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout <"${race_fifo}" >"${race_output}" 2>&1 &
race_process=$!
exec 9>"${race_fifo}"
for _ in {1..200}; do
    grep -Fq 'Disposable host PID to trace:' "${race_output}" && break
    sleep 0.05
done
grep -Fq 'Disposable host PID to trace:' "${race_output}"
printf '%s\n' "${short_pid}" >&9
for _ in {1..200}; do
    grep -Fq 'Single host command:' "${race_output}" && break
    sleep 0.05
done
grep -Fq 'Single host command:' "${race_output}"
kill_owned_node_process "${short_pid}" "${short_start}" "${short_marker}"
for _ in {1..100}; do
    docker exec "${node_name}" test ! -e "/proc/${short_pid}" && break
    sleep 0.05
done
printf '%s\n' id "TRACE-DISPOSABLE-HOST-PROCESS-${short_pid}" >&9
exec 9>&-
wait "${race_process}" || true
output="$(<"${race_output}")"
if [[ "${output}" != *"target is no longer eligible"* && \
      "${output}" != *"open target pidfd: no such process"* ]]; then
    echo "hostPID ptrace target-exit race did not fail closed during app or worker revalidation" >&2
    printf '%s\n' "${output}" >&2
    exit 1
fi

# The timeout command is intentionally harmless. It must terminate only the
# injected child while preserving the test-owned sleep target.
output="$({
    printf '%s\n' "${target_pid}" "sleep 40" \
        "TRACE-DISPOSABLE-HOST-PROCESS-${target_pid}"
} | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
    /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
assert_contains "${output}" "wait for injected child" "command timeout"
[[ "$(docker exec "${node_name}" awk '{print $22}' "/proc/${target_pid}/stat")" == "${target_start}" ]]

# No capture artifact or injected command child may remain in the node.
if docker exec "${node_name}" sh -c 'find /tmp -maxdepth 1 -name ".peirates-ptrace-*" -print -quit | grep -q .' ; then
    echo "hostPID ptrace capture artifact remained in the Kind node" >&2
    exit 1
fi
if docker exec "${node_name}" pgrep -f '^peirates-host$' >/dev/null 2>&1; then
    echo "hostPID ptrace injected child remained in the Kind node" >&2
    exit 1
fi

# User-namespace negative coverage is conditional because many Kind hosts
# prohibit creation of nested user namespaces. Never change node policy.
if docker exec "${node_name}" unshare --user --map-root-user true >/dev/null 2>&1; then
    userns_marker="peirates-userns-${RANDOM}"
    userns_pidfile="/tmp/${userns_marker}.pid"
    docker exec -d "${node_name}" unshare --user --map-root-user --fork /bin/bash -c \
        'echo $$ > "$1"; exec -a "$2" /bin/sleep 60' _ "${userns_pidfile}" "${userns_marker}"
    for _ in {1..100}; do
        docker exec "${node_name}" test -s "${userns_pidfile}" && break
        sleep 0.05
    done
    userns_pid="$(docker exec "${node_name}" cat "${userns_pidfile}")"
    userns_start="$(docker exec "${node_name}" awk '{print $22}' "/proc/${userns_pid}/stat")"
    output="$({ printf '%s\n' "${userns_pid}"; } | timeout 60s kubectl --context "${context}" -n "${namespace}" exec -i "${runner}" -- \
        /tmp/peirates -c -m hostpid-ptrace-breakout 2>&1 || true)"
    assert_contains "${output}" "not in the eligible target list" "nested user namespace target"
    kill_owned_node_process "${userns_pid}" "${userns_start}" "${userns_marker}"
    docker exec "${node_name}" rm -f "${userns_pidfile}"
else
    echo "nested user namespace negative control skipped: node policy does not permit unshare"
fi

echo "main-menu item 32 passed disposable Kind-node ptrace mechanics testing"
