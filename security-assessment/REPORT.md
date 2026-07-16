# AgentBox — Security Assessment

**Target:** `agentbox` (this repository, at `e769695` / v0.25.1)
**Date:** 2026-07-15/16
**Scope:** the box↔host trust boundary as defined in [`SECURITY.md`](../SECURITY.md)
**Method:** multi-agent code audit (10 offensive analysts + adversarial verification of every
finding) followed by hands-on PoC development. See [Methodology](#methodology).

---

## Executive summary

AgentBox's security promise is that a coding agent runs **inside a sandbox and cannot touch the
host**, its credentials, or other boxes. This assessment found that promise is broken on the
default backend and on the cloud/hub paths by several independent defects, including **two
critical box→host remote-code-execution vulnerabilities that require no user interaction**.

The recurring root cause is that the **host relay and host-side sync code treat data that an
untrusted box fully controls (git remotes/args, directory names, credential blobs, status text)
as trusted**, and that several privileged host actions **skip the approval gate**.

| Severity | Count (distinct) | Headline |
|---|---|---|
| **Critical** | 2 | Box→host RCE via the RW `.git/` mount; box→host RCE via the `git.push`/`git.fetch` relay RPCs (no prompt) |
| **High** | 3 | Cross-box RCE via settings propagation; unauthenticated E2B VNC desktop; Control-Hub auth bypass on network profiles |
| **Medium** | 4 | Terminal-escape injection into the host TTY; `CAP_SYS_ADMIN`+unconfined box; arbitrary host-branch clobber; cross-box credential poisoning |
| **Low / Info** | ~9 | Non-constant-time token compares, cross-box network reachability, SSH TOFU, workspace-yaml firewall widening, unauth `/healthz`, origin-URL leakage |

28 candidate findings were raised; each was adversarially verified. 13 survived at medium+ (some
are the same issue found by multiple analysts — consolidated below into **9 distinct medium+
issues**). **8 of the 9 ship with a runnable PoC** validated in this environment; the 9th (E2B
VNC) is cloud-only and documented as a code-grounded walkthrough.

### The two you should fix today

1. **Relay `git.push`/`git.fetch` argument injection → host RCE (Critical).** Any box, using
   the bearer token it legitimately holds, POSTs `/rpc` with a path-like `remote` and
   `--upload-pack=`/`--receive-pack=` in `args`; the host relay runs `git` with those and git
   forks the attacker's program **on the host**, with the host's SSH keys / push tokens / cloud
   keys in its environment. `git.fetch` is **never** gated; `git.push` to the default
   `agentbox/<name>` branch **bypasses** the gate. → [`pocs/relay-git-rpc-rce`](pocs/relay-git-rpc-rce)
2. **RW `.git/` bind mount → host RCE (Critical).** The docker backend mounts the host repo's
   `.git/` read-write; the box writes `.git/hooks/*` or a malicious `.git/config`, and the host
   executes it on the next routine git operation. → [`pocs/docker-git-hook-escape`](pocs/docker-git-hook-escape)

---

## Methodology

The review was structured as a fan-out/verify/exploit workflow driven by subagents:

1. **Scout (inline).** Mapped the ~100K-LOC codebase to the [threat model](#threat-model) and
   pinned the security-critical components: the **host relay** (per-box token + approval gate for
   privileged host actions), the **Control Hub** API, the in-box **ctl** supervisor, **cloud
   credential staging**, and **provider isolation** (esp. docker's RW `.git/` mount).
2. **Find (10 parallel analysts).** One offensive-security analyst per attack surface —
   relay-auth, relay-host-actions, hub-api, docker-isolation, cloud-credentials, hetzner,
   firecracker providers, ctl-supervisor, host-CLI, and a cross-cutting injection sweep. Each was
   grounded in the threat model and told to trace attacker input → sink and name the control that
   should stop it.
3. **Adversarially verify (per finding).** Every candidate finding went to an independent,
   high-effort verifier prompted to **refute** it — re-read the cited code, confirm reachability
   and attacker control, and find the control that blocks it. Severity was re-calibrated on the
   real impact; two findings were refuted, several downgraded.
4. **Exploit + report (inline).** For every confirmed medium+ finding I personally re-read the
   code and built a PoC, preferring to drive the **real shipped code** (the actual relay server,
   the actual `sync-transport`, the actual pinned `better-auth`) over mock-ups.

**Environment note / honesty about fidelity.** This sandbox blocks the Docker registry (so the
real `agentbox/box:dev` image can't be pulled/built) and has no cloud-provider credentials. PoCs
therefore use faithful stand-ins where the full runtime is unreachable (a minimal locally-imported
container image; an HTTP client in the box's network position; a local git bundle for a cloud
bundle). In every case the **vulnerable code path itself is the real thing**; only the
surrounding box/cloud plumbing is modeled. Each PoC's README states exactly what is real vs.
modeled.

---

## Threat model

From [`SECURITY.md`](../SECURITY.md) — the untrusted party is the **agent inside a box**, which
fully controls the box and every byte it sends to the host relay / Control Hub / other boxes. In
scope:

1. A box **escaping its isolation** and reaching host files, credentials, or processes.
2. Host **credentials leaking** into a box or a cloud provider.
3. The relay or Control Hub performing a **host action without the approval gate**, or accepting
   a request **without a valid per-box token**.
4. One box **reading or controlling another box**.

Out of scope: what an agent does with the access it was deliberately given inside its own box;
vulnerabilities in the upstream cloud providers themselves.

---

## Findings

### Distinct medium+ issues (with PoCs)

| ID | Sev | Issue | Threat | PoC |
|---|---|---|---|---|
| C1 | Critical | Box→host RCE via read-write `.git/` bind mount (docker) | #1 | [docker-git-hook-escape](pocs/docker-git-hook-escape) ✅ runnable |
| C2 | Critical | Box→host RCE via `git.push`/`git.fetch` RPC arg injection, gate absent/bypassed | #1,#3 | [relay-git-rpc-rce](pocs/relay-git-rpc-rce) ✅ runnable (real relay) |
| H1 | High | Cross-box RCE via unquoted shell in settings propagation | #4 | [cross-box-propagate-injection](pocs/cross-box-propagate-injection) ✅ runnable (real code) |
| H2 | High | Unauthenticated E2B box VNC desktop on a public URL | #4 | [e2b-vnc-unauth](pocs/e2b-vnc-unauth) 📄 walkthrough (cloud-only) |
| H3 | High | Control-Hub auth bypass on hetzner/vercel (forged cookie + open signup) | #3 | [hub-auth-bypass](pocs/hub-auth-bypass) ✅ runnable (real better-auth) |
| M1 | Medium | Terminal escape-sequence injection into the host TTY | #1 | [terminal-escape-injection](pocs/terminal-escape-injection) ✅ runnable |
| M2 | Medium | Box runs with `CAP_SYS_ADMIN` + seccomp/apparmor unconfined | #1 | [docker-dangerous-caps](pocs/docker-dangerous-caps) ✅ runnable |
| M3 | Medium | `git.push --host-only` force-overwrites arbitrary host branches, no gate (cloud) | #1 | [host-only-branch-clobber](pocs/host-only-branch-clobber) ✅ runnable (real code) |
| M4 | Medium | Cross-box credential poisoning via `credentials-updated`, no gate | #4 | [credentials-fanout-poisoning](pocs/credentials-fanout-poisoning) ✅ runnable (real relay) |

---

### C1 — Box→host RCE via the read-write `.git/` bind mount (Critical)

**Backend:** docker (default). **Location:** `packages/sandbox-docker/src/create.ts:724`.

The docker backend bind-mounts each host repo's `.git/` into the box **read-write** at its
identical host path, with no `:ro`, no `core.hooksPath` redirect, and no filtering of `hooks/` or
`config`. The untrusted agent writes `.git/hooks/pre-commit` (or `post-checkout`,
`reference-transaction`, …) or a malicious `.git/config` (`core.fsmonitor`, `core.pager`,
`core.sshCommand`, `[alias] x = !cmd`, …), and git executes it **on the host** on the next
routine git operation in that repo — reviewing/committing, checking out between boxes, pulling,
pushing (the tray app has buttons for all of them). `safe.directory` does not help: the repo is
legitimately host-owned.

**PoC:** [`pocs/docker-git-hook-escape`](pocs/docker-git-hook-escape) reproduces the exact mount
with an *unprivileged* uid-1000 container and lands code execution in the host user's home on a
routine `git commit`/`git status`.

**Fix:** mount `.git` read-only and broker commits through the relay; or mount only objects+refs
and keep `hooks/`+`config` host-only; run host git with `-c core.hooksPath=/dev/null -c core.fsmonitor=false` as defense in depth.

---

### C2 — Box→host RCE via `git.push`/`git.fetch` relay RPCs (Critical)

**Backends:** all (host relay; docker directly, cloud via the executor twin). **Location:**
`packages/relay/src/server.ts:1582-1590`, gate scoping `:534,563,583-593`;
`packages/core/src/sync/git-refs.ts:47-49,99-101`; cloud twin
`packages/relay/src/host-actions.ts:1318-1321,1367-1368`. *(Found independently by the relay-auth,
relay-host-actions, and injection analysts; the cli-host analyst found the same remote-validation
gap.)*

The relay runs git on the host from box-controlled, unvalidated input:

```ts
const remote = resolveRemote(params?.remote);            // `remote ?? 'origin'` — NO validation
const argv = ['git','-C', worktree.hostMainRepo, op, remote, pushBranch];
argv.push(...sanitizeGitArgs(params?.args));             // type-filter ONLY
await runHostCommand(argv);                              // spawn(cmd, rest, { env: process.env })
```

There is no shell, but **git itself forks the program named by `--upload-pack=` (fetch) /
`--receive-pack=` (push)** for a path-like remote. So `remote="/x"` + `args=["--upload-pack=sh -c
'…'"]` → arbitrary host command execution with the host user's SSH keys / push tokens / cloud keys
in the environment. The approval gate does not stop it: `git.fetch` is never gated (the whole gate
block is `if (body.method === 'git.push')`), and `git.push` to the default `agentbox/<name>`
scratch branch sets `bypassPushGate`.

**PoC:** [`pocs/relay-git-rpc-rce`](pocs/relay-git-rpc-rce) boots the **real relay**, and — with
only a box bearer token — runs code on the host and exfiltrates a host secret via **both** the
ungated `git.fetch` and the gate-bypassing `git.push` paths, **with no approval prompt**.

**Fix:** allow-list `args` (deny `--upload-pack`/`--receive-pack`/`--exec`/`-o`/`--config`);
reject any `remote` that isn't a configured remote name; gate `git.fetch` like `git.push`;
reconsider the unconditional scratch-branch bypass now that `args` is attacker-influenced.

---

### H1 — Cross-box RCE via shell injection in settings propagation (High)

**Backends:** cloud (e2b/vercel/daytona); docker config-volume twin. **Location:**
`packages/sandbox-cloud/src/sync/sync-transport.ts:62-65` (and `pushFile`/`pullTree`);
`packages/sandbox-core/src/sync/agent-propagate.ts:146,170-173`; taint filter
`packages/sandbox-core/src/sync/claude-pull.ts` `pickNewItems`.

`agentbox download claude <src> --propagate` copies skill/agent/command **directory names** from a
source box into every other box. Those names are agent-controlled (a Linux dir name may contain
`;`/`$`/`|`/`` ` ``) and are filtered only for host-presence / an `agentbox-` prefix — never for
shell metacharacters. They reach the target box through `applyTarball`, which interpolates the
destination dir **unquoted** into `tar -xf … -C ${boxDestDir} …` and hands it to `backend.exec`
(a shell in the target box), bypassing the `quoteShellArgv` the argv-taking `exec()` uses.

**PoC:** [`pocs/cross-box-propagate-injection`](pocs/cross-box-propagate-injection) drives the
**real** `createCloudSyncTransport`/`applyTarball` and runs an injected command inside a *different*
box from the attacker's.

**Fix:** route `applyTarball`/`pushFile`/`pullTree` through argv arrays / `quoteShellArgv`;
allow-list item names (`[A-Za-z0-9._-]+`) in `pickNewItems`; same fix for the docker twin.

---

### H2 — Unauthenticated E2B box VNC desktop on a public URL (High)

**Backend:** e2b. **Location:** `packages/sandbox-docker/scripts/agentbox-vnc-start:27-40`;
`packages/sandbox-e2b/src/backend.ts:407-421`.

On E2B's Debian 12 base `vncpasswd` is absent, so Xvnc falls back to `-SecurityTypes None` (no VNC
auth), "relying on the preview URL as the access boundary." But the E2B preview URL is **public
with no token** (`https://{port}-{sandboxId}.e2b.app`, `signedPreviewUrl` is a no-op), and the
`sandboxId` is the hostname of the user's own **public app preview** URL. Anyone who learns it
opens a full, unauthenticated interactive desktop in the box.

**PoC:** [`pocs/e2b-vnc-unauth`](pocs/e2b-vnc-unauth) — cloud-only walkthrough with exact cites and
repro steps.

**Fix:** never start Xvnc with `-SecurityTypes None`; mint a random per-box VNC secret even
without `vncpasswd`, or front it with an authenticated proxy; treat the preview URL as public.

---

### H3 — Control-Hub auth bypass on the hetzner/vercel profiles (High)

**Component:** Control Hub. **Location:** `apps/hub/proxy.ts:46-49,92-95`; `apps/hub/lib/auth.ts:47`;
`apps/hub/server.ts:29`.

On the network profiles the hub binds `0.0.0.0` and auto-enables auth, but the only gate for
`/api/v1/*` (box lifecycle, git push, approval answers) and the dashboard is
`if (getSessionCookie(request)) return NextResponse.next()`. better-auth's `getSessionCookie`
does **no** validation (no signature, no DB lookup, no expiry/revocation), and no handler
re-checks the session — so **any non-empty `better-auth.session_token` cookie passes**.
Independently, `emailAndPassword: { enabled: true }` with no `disableSignUp` and an ungated
`/api/auth/sign-up/email` lets any network client **self-register a real session**. Either way an
unauthenticated client can destroy boxes, push the box branch with the host's token, and **answer
approval prompts `y`** — defeating the host-action approval gate.

**PoC:** [`pocs/hub-auth-bypass`](pocs/hub-auth-bypass) drives the **verbatim** proxy gate with the
**real pinned `better-auth@1.6.23`**; a forged cookie passes all privileged routes.

**Fix:** validate the session with `auth.api.getSession` (DB-backed) instead of `getSessionCookie`
presence; set `disableSignUp: true` (+ invite/allow-list); add ownership authz; don't serve the
control plane over plain HTTP on `0.0.0.0`.

---

### M1 — Terminal escape-sequence injection into the host TTY (Medium)

**Backends:** all. **Location:** `packages/ctl/src/socket.ts:158-171`,
`status-reporter.ts:114-127`; sinks `apps/cli/src/commands/agent.ts:143,148-150`,
`wrapped-pty/footer.ts`, `dashboard/sidebar.ts`; unused sanitizer `apps/cli/src/terminal/title.ts:7-9`.

The box sets free-text `plan`/`question`/session-title fields; the ctl socket validates only the
`state` enum and forwards the rest verbatim to the host, which renders them to the operator's TTY
with no control-char stripping. A box emits **OSC-52** (writes an attacker command to the host
clipboard → host RCE on the operator's next paste) or **cursor/erase** sequences (forge the
approval-prompt chrome). The project's own `sanitize()` is applied only to the OSC-title path.

**PoC:** [`pocs/terminal-escape-injection`](pocs/terminal-escape-injection) shows the raw OSC-52 +
CSI bytes reaching the operator's stream via the real sink, and that `sanitize()` would neutralize
them.

**Fix:** apply `sanitize()` to every box-originated string rendered to a host TTY, and/or strip at
the relay/socket ingress.

---

### M2 — Box runs with `CAP_SYS_ADMIN` + seccomp/apparmor unconfined (Medium)

**Backend:** docker. **Location:** `packages/sandbox-docker/src/docker.ts:54-78`.

Every box launches with `--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --device=/dev/fuse
--security-opt=apparmor:unconfined --security-opt=seccomp=unconfined`. This removes the two filters
Docker relies on and grants `mount()`/`pivot_root`. It is a deliberate trade-off for the in-box
dockerd, but a real isolation regression: seccomp-off lets the untrusted agent issue any syscall,
and on cgroup-v1/hybrid hosts `CAP_SYS_ADMIN`+`mount` is the entry point for the classic
`release_agent` container→host breakout.

**PoC:** [`pocs/docker-dangerous-caps`](pocs/docker-dangerous-caps) shows, against the exact flags,
`CAP_SYS_ADMIN` present, seccomp off, and a privileged `mount` succeeding where a default container
is denied.

**Fix:** scope the capabilities/seccomp relaxation to only what the in-box dockerd needs (a tailored
seccomp profile rather than `unconfined`), or isolate the DinD in a nested user namespace; prefer
rootless/`sysbox`-style runtimes where available.

---

### M3 — `git.push --host-only` force-overwrites arbitrary host branches (Medium)

**Backends:** cloud (on docker the box already has RW `.git/`, so no delta). **Location:**
`packages/relay/src/host-actions.ts:1136-1162`; refspec `packages/core/src/sync/git-refs.ts:56-67`.
*(The docker path of this primitive was refuted — it uses a host-controlled source branch; the
cloud path is the confirmed issue.)*

`git.push` with `params.hostOnly` short-circuits the approval gate, then runs `git fetch <bundle>
<refspec>` where `refspec = +<branch>:refs/heads/<dest>` with `dest`/`force` box-controlled and (on
cloud) `branch` = the box's own HEAD. A box force-overwrites any non-checked-out host branch (e.g.
`main`) to attacker commits with no prompt; the developer may later push or build from it.

**PoC:** [`pocs/host-only-branch-clobber`](pocs/host-only-branch-clobber) uses the real refspec
builders and force-overwrites host `main`.

**Fix:** gate the host-only land like a push, or restrict `dest` to the box's sanctioned branch and
refuse box-supplied `force`.

---

### M4 — Cross-box credential poisoning via `credentials-updated` (Medium)

**Backends:** all (host relay). **Location:** `packages/relay/src/server.ts:494`;
`packages/relay/src/credentials-fanout.ts:66-100`;
`packages/sandbox-core/src/sync/concerns/credentials.ts` (`shouldAcceptCredentialUpdate`).

Any box POSTs `/events {type:'credentials-updated', …}` with its own token. The relay accepts it if
the claude blob has a (attacker-chosen) `refreshToken`, and its "newest-wins" ordering keys on the
**box-supplied** `expiresAt` — so a far-future value always wins. On accept the relay **overwrites
the host credential backup** and fans the blob out to **every other box**, with no approval prompt
and no audit entry. It does not steal the host's real secret, but it tampers with a shared
security-relevant store across the trust boundary (DoS / forced identity).

**PoC:** [`pocs/credentials-fanout-poisoning`](pocs/credentials-fanout-poisoning) drives the real
relay `/events` and replaces the host backup with attacker content.

**Fix:** gate `credentials-updated` (approval / host-initiated) or bind it to a host-designated
box; don't derive the ordering key from untrusted input; audit-log the event.

---

### Lower-severity findings

Confirmed, lower impact — worth fixing but not gating:

- **Non-constant-time per-box token comparison** (`registry.ts:authenticate` plain `===` linear
  scan; also the in-box relay bridge/box token). Timing side channel on a 256-bit token; low.
  Found by 5 analysts (relay-auth, relay-host-actions, cloud-credentials, injection, firecracker).
  → use `crypto.timingSafeEqual` on a fixed-length hash.
- **Boxes are not network-isolated from each other** (shared default docker bridge) — a box can
  reach another box's exposed services. → per-box network.
- **Cloud workspace seed copies the host origin URL verbatim** into the box git config / snapshot —
  leaks an embedded credential if the origin is a tokenized HTTPS URL. → strip credentials from
  origin before seeding.
- **Hetzner SSH first-connect is TOFU** (`StrictHostKeyChecking=accept-new`) — first-connect MITM
  risk. → pin the host key from the create API response.
- **Repo-supplied `agentbox.yaml` can widen the per-box SSH firewall** (workspace config layer) —
  a malicious repo loosens the box's ingress. → don't let the workspace layer control the firewall
  scope.
- **Unauthenticated `/healthz`** on both the host relay and the internet-exposed in-box relay —
  discloses pid / version / commit / box+event counts. → drop or authenticate it on the public
  surface.

**Refuted during verification:** the hetzner cloud-init "box name injection" (the box name is
host-chosen at create, not box-controlled — latent, not reachable); and the *docker* variant of the
host-only branch clobber (host-controlled source branch — the cloud variant M3 is the real issue).

---

## Cross-cutting themes & prioritized remediation

Three systemic patterns account for almost every high-impact finding:

1. **Box-controlled data reaches a host-side command/sink unvalidated.** git remotes+args
   (C2), directory names (H1), branch destinations (M3), credential blobs (M4), status text
   (M1). *Systemic fix:* treat every field arriving from a box as hostile at the relay/sync
   boundary — allow-list, never blocklist; use argv arrays, never string interpolation; never let
   a value from a box pick a program for git/tar/shell to exec.
2. **Privileged host actions skip the approval gate.** `git.fetch` (C2), scratch-branch
   `git.push` (C2), `--host-only` land (M3), `credentials-updated` (M4). *Systemic fix:* make the
   gate the default for every host-mutating/host-executing RPC; bypasses should be explicit
   allow-lists of provably-safe operations, re-audited now that argv is attacker-influenced.
3. **"The URL/cookie/mount is the boundary" assumptions that aren't boundaries.** Public
   tokenless preview URLs fronting an unauth VNC (H2); `getSessionCookie` presence as
   authorization (H3); a RW `.git/` mount as if the box only reads it (C1). *Systemic fix:*
   independent auth on every exposed surface; validate sessions, not cookie presence; least
   privilege on mounts.

**Suggested order:** C2 and C1 (critical, no-interaction, default paths) → H3 (network-facing auth
bypass) → H1 (cross-box RCE) → H2 (public desktop) → M1–M4 → lows. The container-hardening item
(M2) is a larger architectural change (DinD vs. isolation) and can be scheduled deliberately.

---

## Appendix — PoC index

All PoCs live under [`pocs/`](pocs). Runnable ones were validated in this environment; each README
states what is real vs. modeled and how to run it.

| PoC | Kind | Proves |
|---|---|---|
| [docker-git-hook-escape](pocs/docker-git-hook-escape) | bash + docker | C1: box writes host `.git/hooks` → host RCE |
| [relay-git-rpc-rce](pocs/relay-git-rpc-rce) | node, real relay | C2: box token → host RCE + secret exfil, no prompt |
| [cross-box-propagate-injection](pocs/cross-box-propagate-injection) | node, real transport | H1: box name → RCE in another box |
| [hub-auth-bypass](pocs/hub-auth-bypass) | node, real better-auth | H3: forged cookie → privileged hub routes |
| [e2b-vnc-unauth](pocs/e2b-vnc-unauth) | walkthrough | H2: public tokenless URL → unauth desktop |
| [terminal-escape-injection](pocs/terminal-escape-injection) | node | M1: OSC-52/CSI reach host TTY raw |
| [docker-dangerous-caps](pocs/docker-dangerous-caps) | bash + docker | M2: CAP_SYS_ADMIN + seccomp off + privileged mount |
| [host-only-branch-clobber](pocs/host-only-branch-clobber) | node, real refspec | M3: box force-overwrites host `main`, no gate |
| [credentials-fanout-poisoning](pocs/credentials-fanout-poisoning) | node, real relay | M4: box overwrites shared host credential backup |
