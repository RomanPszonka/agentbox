# PoC — Cross-box credential poisoning via the relay `credentials-updated` event

**Severity: Medium** · Threat-model items #4 (control another box) + #1 (write a host state file
with attacker content) · All backends with a host relay · No approval prompt, not audited.

## The bug

A box POSTs `/events {type:'credentials-updated', payload:{agent, contentBase64}}` with its own
bearer token. In host mode the relay runs `CredentialsFanout.handle` (`server.ts:494`):

```ts
// packages/relay/src/credentials-fanout.ts:66-81
const update = parseCredentialsUpdate(payload);                 // claude: only needs a non-empty refreshToken
const existing = await readCredentialBackup(update.agent, …);
const verdict = shouldAcceptCredentialUpdate(update.agent, update.content, existing);  // newest-wins on attacker expiresAt
if (!verdict.accept) return …;
await writeCredentialBackup(update.agent, update.content, …);   // OVERWRITE host backup
this.schedule(update.agent, sourceBoxId);                       // spawn `agentbox credentials propagate` (scope: all)
```

`shouldAcceptCredentialUpdate`'s "newest-wins" for claude keys on `claudeAiOauth.expiresAt` —
which is **inside the box-supplied blob** — so a far-future value always wins over the host's
real backup. On accept the relay overwrites `~/.agentbox/claude-credentials.json` and fans the
blob out to **every other box** (docker config volumes incl. paused boxes, and every running
cloud box). `authBox` only checks the box holds a valid token (every box does); there is **no
approval prompt**, and the event is deliberately excluded from the audit ring buffer.

## What the PoC proves

`poc.mjs` isolates `HOME` to a temp dir, seeds a legit backup, then — as a box holding only its
bearer token — POSTs the poisoned event to the **real relay**:

```
1. host backup refreshToken = REAL-USER-REFRESH-TOKEN
3. box POSTs credentials-updated (refreshToken="ATTACKER-CONTROLLED-TOKEN", expiresAt=99999999999999)
   POST /events -> HTTP 202
4. host backup refreshToken is now: ATTACKER-CONTROLLED-TOKEN   (accepted: "newer expiresAt")
VULNERABLE
```

`AGENTBOX_CLI_ENTRY` is left unset so the fan-out spawn only logs a failure instead of pushing
into real boxes; in production it runs `credentials propagate --agent claude` (scope: all).

## Running it

```bash
pnpm install && pnpm --filter @agentbox/relay... build
node security-assessment/pocs/credentials-fanout-poisoning/poc.mjs
```

## Fix directions

- Gate `credentials-updated` behind the same approval/host-initiated mechanism as `git.push`,
  or restrict which box may update a given agent's shared credential (e.g. only a box the host
  explicitly designated), and record the event in an audit log.
- Do not let the ordering key (`expiresAt`) come from untrusted box input; treat a
  refresh-token rotation as authoritative only when it verifiably chains from the prior token.
