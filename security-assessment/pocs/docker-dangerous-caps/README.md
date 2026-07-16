# PoC — Docker box runs with a heavily weakened confinement profile

**Severity: Medium** · Threat-model item #1 (weakening the box→host isolation boundary) ·
Backend: docker (default).

## The bug

Every box is launched with (`packages/sandbox-docker/src/docker.ts:54-78`):

```
--cap-add=SYS_ADMIN  --cap-add=NET_ADMIN  --device=/dev/fuse
--security-opt=apparmor:unconfined  --security-opt=seccomp=unconfined  --cgroupns=private
```

`seccomp=unconfined` + `apparmor:unconfined` remove the two filters Docker relies on to keep a
hostile container off dangerous kernel surface, and `CAP_SYS_ADMIN` unlocks `mount()`/`pivot_root`.
This is a deliberate trade-off to run the in-box `dockerd`, but it is a real isolation regression:
the untrusted agent can issue **any** syscall and holds `CAP_SYS_ADMIN`. On cgroup-v1 / hybrid
hosts (many Linux hosts and CI runners) this is the precondition for the classic `release_agent`
container→host breakout; on cgroup-v2-only hosts (modern Docker Desktop / OrbStack) that specific
technique is mitigated but the removed seccomp/apparmor still broadly widen the attack surface.

The box is *not* `--privileged`, does not mount the docker socket, and does not share host
PID/net/IPC namespaces — so those specific escapes are absent; the regression is the removed
syscall/LSM filtering plus `CAP_SYS_ADMIN`.

## What the PoC proves

`poc.sh` runs a probe container with the **exact** box flags and contrasts it with a
default-hardened container:

```
default flags:   CapEff=00000000a80425fb  CAP_SYS_ADMIN=absent   Seccomp=filter(2)  privileged mount=denied
box flags:       CapEff=00000000a82435fb  CAP_SYS_ADMIN=PRESENT  Seccomp=OFF(0)     privileged mount=OK
ISOLATION WEAKENED
```

The box holds `CAP_SYS_ADMIN`, has the seccomp filter disabled, and can perform a privileged
`mount()` the default container is denied. (A full host breakout is host-config-dependent — cgroup
v1 — so the PoC demonstrates the *precondition*, not a completed escape.)

## Running it

```bash
bash security-assessment/pocs/docker-dangerous-caps/poc.sh   # needs docker
```

## Fix directions

- Replace `seccomp=unconfined` with a **tailored seccomp profile** that allows only the syscalls
  the in-box dockerd actually needs; likewise scope AppArmor rather than disabling it.
- Isolate the DinD in a nested user namespace, or use a rootless / `sysbox`-style runtime so the
  outer box does not need host-level `CAP_SYS_ADMIN`.
- Where DinD isn't required, launch the box without these relaxations at all.
