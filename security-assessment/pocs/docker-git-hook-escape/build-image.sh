#!/usr/bin/env bash
#
# Build a minimal stand-in "box" image (agentbox-poc-mini:latest) WITHOUT a
# registry pull, by importing a tiny rootfs assembled from the host's own
# shell + coreutils. This exists only because this CI sandbox blocks the docker
# registry; on a normal host you would use the real `agentbox/box:dev` image and
# skip this script entirely.
#
# The image just needs to run a shell as an arbitrary uid and write files into a
# bind mount -- that is all the PoC's "box" side does.
set -euo pipefail

IMAGE="${POC_IMAGE:-agentbox-poc-mini:latest}"
tmp="$(mktemp -d)"; root="$tmp/rootfs"
mkdir -p "$root"/{bin,usr/bin,lib/x86_64-linux-gnu,lib64}

BINS=(/bin/bash /bin/dash /usr/bin/id /usr/bin/hostname /bin/cat /usr/bin/whoami
      /usr/bin/env /bin/chmod /usr/bin/tee /bin/ls /usr/bin/date /bin/uname)
for b in "${BINS[@]}"; do [ -e "$b" ] && cp -aL "$b" "$root${b}" 2>/dev/null || true; done
ln -sf dash "$root/bin/sh"

# every shared lib the above need, dereferenced, plus the ELF loader
for b in "${BINS[@]}"; do
  [ -e "$b" ] && ldd "$b" 2>/dev/null | grep -oE '/lib[^ ]*\.so[^ ]*' || true
done | sort -u | while read -r lib; do cp -aL "$lib" "$root/lib/x86_64-linux-gnu/" 2>/dev/null || true; done
cp -aL /lib64/ld-linux-x86-64.so.2 "$root/lib64/ld-linux-x86-64.so.2"

( cd "$root" && tar -cf - . ) | docker import - "$IMAGE" >/dev/null
rm -rf "$tmp"
echo "built $IMAGE"
docker run --rm --user 1000:1000 "$IMAGE" /bin/bash -c 'echo ok: $(id -u)'
