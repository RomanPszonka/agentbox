# PoC — `git.push --host-only` force-overwrites arbitrary host local branches

**Severity: Medium** · Threat-model item #1 (mutate host repo state the box shouldn't reach) ·
Cloud backends (daytona/hetzner/vercel/e2b) — on docker the box already has RW `.git/`, so this
adds nothing there · No approval prompt.

## The bug

`git.push` with `params.hostOnly` short-circuits the confirm / host-initiated-token gate
("landing publishes nothing, so the push-confirm gate doesn't apply") and then runs:

```ts
// packages/relay/src/host-actions.ts:1136-1162  (cloud runGitRpc, hostOnly block)
const dest = resolveLandDest(branch, params.as);          // box-controlled `as`  (git-refs.ts:56)
const refspec = landRefspec(branch, dest, params.force);  // box-controlled `force`(git-refs.ts:65) -> `+<branch>:refs/heads/<dest>`
await execa('git', ['-C', hostWorkspace, 'fetch', hostBundleSave, refspec], { reject: false });
```

On the cloud path `branch` is resolved from `git rev-parse --abbrev-ref HEAD` **inside the
sandbox** (agent-controlled), and `as`/`force` come straight off the wire. So a box lands **any
box-authored commits** onto **any non-checked-out host local branch** (e.g. `main`) with **no
approval prompt**. git's ref-name validation blocks `..`/path traversal, so this is a branch-ref
rewrite, not arbitrary file write — but poisoning local `main` means the developer may later
`git push origin main` or build from it and ship attacker code.

## What the PoC proves

`poc.mjs` uses the **real** `resolveLandDest`/`landRefspec` from `@agentbox/core` and runs the
exact `git fetch <bundle> <refspec>` the handler runs:

```
resolveLandDest("poison","main") = "main"
landRefspec("poison","main",force=true) = "+poison:refs/heads/main"
host main was 3f696c86ec ("real work on main") -> now a799d31088 ("backdoor")
VULNERABLE
```

The refspec construction and the git force-overwrite are the real thing; the cloud bundle
download / in-sandbox HEAD resolution are represented by a local bundle (no cloud creds in this
environment).

## Running it

```bash
pnpm install && pnpm --filter @agentbox/core build
node security-assessment/pocs/host-only-branch-clobber/poc.mjs
```

## Fix directions

- Gate the `hostOnly` land the same way as a remote push, or restrict the destination to the
  box's own sanctioned/scratch branch (reject a box-chosen `as` that names another branch).
- Refuse `force` from box input, or require host-initiated approval when `as` != the box's
  create-time branch.
