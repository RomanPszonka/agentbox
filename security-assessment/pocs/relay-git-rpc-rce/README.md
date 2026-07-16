# PoC — Box → Host RCE via the `git.push` / `git.fetch` relay RPCs

**Severity: Critical** · Threat-model items #1 (box→host RCE, host-credential theft) + #3
(approval gate absent/bypassed) · **All backends** with a host relay (docker, and the cloud
executor twin) · **No user interaction** — no approval prompt is shown.

## The bug

The host relay runs git on the host for a box. The argv is built from **box-controlled,
unvalidated** input:

```ts
// packages/relay/src/server.ts:1582-1590  (handleGitRpc)
const remote = resolveRemote(params?.remote);                 // git-refs.ts:47  -> `remote ?? 'origin'`, NO validation
const pushBranch = worktree.sanctionedBranch ?? worktree.branch;
const argv = ['git', '-C', worktree.hostMainRepo, op, remote, pushBranch];
argv.push(...sanitizeGitArgs(params?.args));                  // git-refs.ts:99  -> type-filter ONLY
const result = await runHostCommand(argv);                    // server.ts:2079 -> spawn(cmd, rest, { env: process.env })
```

`remote` and `args` come straight off the wire. There is no shell, but **git itself forks the
program named by `--upload-pack=` (fetch) / `--receive-pack=` (push)** when the remote is a
path (git's local transport). So a box that sends `remote = "/any/path"` and
`args = ["--upload-pack=sh -c '…'"]` gets arbitrary command execution on the host, running
with the relay's environment — the host user's SSH keys, git push tokens, cloud API keys, etc.

`sanitizeGitArgs` only keeps strings (`git-refs.ts:99-101`); it does not strip
`--upload-pack` / `--receive-pack` / `--exec` / `-o` / `--config`. `resolveRemote`
(`git-refs.ts:47-49`) does not check that `remote` is a configured remote *name*.

### The approval gate does not stop it

- **`git.fetch` is never gated.** The entire approval block is wrapped in
  `if (body.method === 'git.push')` (`server.ts:563`); `git.fetch` falls straight through to
  `handleGitRpc` at `server.ts:653`.
- **`git.push` to the box's own `agentbox/<name>` scratch branch is bypassed.**
  `bypassPushGate = isScratch || …` and `isScratch = isScratchBranch(dockerPushBranch)`
  (`server.ts:583-593`). Every box's default branch *is* `agentbox/<name>`, so the gate is
  skipped there too.

The cloud path has the identical construction in `host-actions.ts:1318-1321` (push) and
`:1367-1368` (fetch).

## What the PoC proves

`poc.mjs` boots the **real relay** (`packages/relay/dist`) in host mode with its default
in-memory store, registers a box, then — presenting **only the box's bearer token**, exactly
as an in-box agent does (the token is in the box's env / `/run/agentbox/relay.env`) — sends
the two RPCs:

```
VULNERABLE -- a box with only its bearer token ran code on the HOST:
     PWNED via git.push scratch-branch
     uid=0(root) gid=0(root) groups=0(root)
     vm                                   <- host
     HOST SECRET EXFILTRATED -> .../STOLEN_HOST_KEY:
        "SUPER-SECRET-HOST-SSH-KEY-DO-NOT-LEAK"
   git.fetch path executed: true   git.push scratch-branch path executed: true
   relay ever prompted/gated for approval: NO
```

Both the ungated `git.fetch` and the gate-bypassing `git.push` scratch-branch paths execute,
a stand-in host SSH key is exfiltrated, and no approval is ever requested. (The `/rpc` calls
return HTTP 500 because git ultimately fails against the bogus remote path — but the
`--upload-pack`/`--receive-pack` program has already run.)

## Running it

```bash
pnpm install && pnpm --filter @agentbox/relay... build   # build the real relay
node security-assessment/pocs/relay-git-rpc-rce/poc.mjs
```

The PoC uses the box's network position faithfully (an HTTP client that holds the box token);
it does not need a container, because the vulnerability is that the relay executes
box-controlled argv on the host for any request bearing a valid box token.

## Fix directions

- In `sanitizeGitArgs`, **deny** `--upload-pack`, `--receive-pack`, `--exec`, `-u`, `-o`,
  `--config`/`-c`, and anything starting with `--upload-pack=`/`--receive-pack=` (allow-list
  the handful of args the box path actually needs instead of blocklisting).
- In `resolveRemote`, reject any `remote` that is not a **configured remote name** (no
  slashes, no `:`, no `.` path forms, must exist in `git remote`).
- Route **`git.fetch` through the same approval/host-initiated gate** as `git.push` (it is not
  read-only when the box chooses the remote and transport).
- Reconsider the unconditional scratch-branch bypass now that the argv tail is attacker-influenced.
