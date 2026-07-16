#!/usr/bin/env bash
#
# PoC: the docker box runs with a heavily weakened confinement profile
# ---------------------------------------------------------------------------
# Every docker box is launched with (packages/sandbox-docker/src/docker.ts:54-78):
#
#     --cap-add=SYS_ADMIN  --cap-add=NET_ADMIN  --device=/dev/fuse
#     --security-opt=apparmor:unconfined  --security-opt=seccomp=unconfined
#     --cgroupns=private
#
# seccomp=unconfined + apparmor=unconfined remove the two filters Docker relies on
# to keep a hostile container off dangerous kernel surface, and CAP_SYS_ADMIN
# unlocks mount()/pivot_root/etc. This is a deliberate trade-off for the in-box
# dockerd, but it is a real isolation regression: the untrusted agent (seccomp
# off) can issue arbitrary syscalls and hold CAP_SYS_ADMIN. On cgroup-v1 / hybrid
# hosts this is the precondition for the classic release_agent container->host
# breakout; on cgroup-v2-only hosts it "merely" widens the kernel attack surface.
#
# This PoC contrasts the EXACT box flags against a default-hardened container:
# it shows CAP_SYS_ADMIN present, the seccomp filter OFF, and a privileged
# mount() succeeding inside the box where the default container is denied.
#
# Requirements: docker. Safe: no host mounts, throwaway image, no escape performed.

set -euo pipefail
IMAGE="agentbox-poc-caps:latest"
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

# The exact security-relevant flags from docker.ts runBox().
BOX_FLAGS=(--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --device=/dev/fuse
           --security-opt=apparmor:unconfined --security-opt=seccomp=unconfined
           --cgroupns=private)

say "0. Build a tiny probe image (registry blocked here; import a host rootfs)"
tmp="$(mktemp -d)"; root="$tmp/rootfs"
mkdir -p "$root"/{bin,usr/bin,lib/x86_64-linux-gnu,lib64,mnt,proc}
BINS=(/bin/bash /bin/dash /bin/cat /usr/bin/mount /usr/bin/id /bin/uname /usr/sbin/capsh)
for b in "${BINS[@]}"; do [ -e "$b" ] && cp -aL "$b" "$root${b}" 2>/dev/null || true; done
ln -sf dash "$root/bin/sh"
for b in "${BINS[@]}"; do [ -e "$b" ] && ldd "$b" 2>/dev/null | grep -oE '/lib[^ ]*\.so[^ ]*' || true; done \
  | sort -u | while read -r l; do cp -aL "$l" "$root/lib/x86_64-linux-gnu/" 2>/dev/null || true; done
cp -aL /lib64/ld-linux-x86-64.so.2 "$root/lib64/ld-linux-x86-64.so.2"
( cd "$root" && tar -cf - . ) | docker import - "$IMAGE" >/dev/null
rm -rf "$tmp"
info "built $IMAGE"

PROBE='cat /proc/self/status | while read k v; do case "$k" in CapEff:|Seccomp:) echo "$k $v";; esac; done; printf "MOUNT: "; mount -t tmpfs tmpfs /mnt 2>&1 && echo OK || echo DENIED'

decode() { # $1 = run label, rest = docker flags
  local label="$1"; shift
  local out capeff seccomp mount sysadmin
  out="$(docker run --rm "$@" "$IMAGE" /bin/sh -c "$PROBE" 2>&1 || true)"
  capeff="$(printf '%s\n' "$out" | awk '/CapEff:/{print $2}')"
  seccomp="$(printf '%s\n' "$out" | awk '/Seccomp:/{print $2}')"
  mount="$(printf '%s\n' "$out" | awk '/MOUNT:/{print $2}')"
  if [ -n "$capeff" ] && (( (0x$capeff >> 21) & 1 )); then sysadmin="PRESENT"; else sysadmin="absent"; fi
  local sec="filter(2)"; [ "$seccomp" = "0" ] && sec="OFF(0)"
  printf '   %-26s CapEff=%s  CAP_SYS_ADMIN=%-8s Seccomp=%-10s privileged mount=%s\n' \
    "$label" "$capeff" "$sysadmin" "$sec" "$mount"
  # export for the caller's assertions
  LAST_SYSADMIN="$sysadmin"; LAST_SECCOMP="$seccomp"; LAST_MOUNT="$mount"
}

say "1. A DEFAULT-hardened container (what Docker gives you normally)"
decode "default flags:"

say "2. The AgentBox box (exact docker.ts flags)"
decode "box flags:" "${BOX_FLAGS[@]}"

say "3. Result"
if [ "$LAST_SYSADMIN" = "PRESENT" ] && [ "$LAST_SECCOMP" = "0" ] && [ "$LAST_MOUNT" = "OK" ]; then
  printf '\033[1;31mISOLATION WEAKENED\033[0m -- the box holds CAP_SYS_ADMIN, has the seccomp filter\n'
  info "disabled, and can perform privileged mount() operations the default container cannot."
  info "seccomp=unconfined lets the untrusted agent issue ANY syscall; CAP_SYS_ADMIN + mount()"
  info "is the entry point for cgroup-v1 release_agent-style host breakouts and broad kernel"
  info "attack surface. This is a deliberate DinD trade-off but a real regression vs a default box."
  RC=0
else
  printf '\033[1;32mInconclusive on this host\033[0m (cgroup/engine specifics).\n'; RC=1
fi
docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
exit $RC
