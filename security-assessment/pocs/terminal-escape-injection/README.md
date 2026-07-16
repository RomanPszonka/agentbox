# PoC — Terminal escape-sequence injection from a box into the host terminal

**Severity: Medium** · Threat-model item #1 (box escaping the display/clipboard isolation of the
host terminal) · All backends · Triggers when the operator runs `agentbox agent
get-plan-question`, `claude attach`, or opens the dashboard.

## The bug

The untrusted in-box agent drives the ctl socket with a `claude-state` update whose
`plan`/`question`/session-title fields are free text. `socket.ts` validates only the `state`
enum and forwards the rest verbatim; `status-reporter.ts` puts them in the `BoxStatus` POSTed
to the relay; the relay and host persist them with a **schema check only**. Host renderers then
write them to the operator's TTY with **no control-char stripping**:

```ts
// apps/cli/src/commands/agent.ts:143  (`agentbox agent get-plan-question`)
process.stdout.write(claude.plan.plan + '\n');            // raw box bytes -> host TTY
// and: q.question / option labels (:148-150); the `claude attach` alert band (footer.ts padTo);
//      the dashboard sidebar (sidebar.ts)
```

The project already ships the right sanitizer — `sanitize()` in `apps/cli/src/terminal/title.ts:7-9`
(`replace(/[\x00-\x1f\x7f]/g, ' ')`) — but applies it **only** to the OSC-0 terminal-title path,
never to these status fields.

## What the PoC proves

`poc.mjs` builds the box-controlled `plan` (an **OSC-52** clipboard write + a **CSI** cursor/erase
chrome-forge), drives the **verbatim** host sink, and inspects the bytes:

```
2. bytes written to the operator's stream: 135
     contains raw OSC-52 clipboard-write sequence: true
     contains raw CSI cursor/erase (chrome forge):  true
3. sanitize(plan) still contains escapes: false        <- the in-tree fix would neutralize it
VULNERABLE
```

**Impact:** (1) OSC-52 writes an attacker command into the **host clipboard**, so the operator's
next paste into a host shell runs it (host RCE, gated on paste + a terminal that honors OSC-52
writes — iTerm2, kitty, xterm with `allowWindowOps`, etc.); (2) cursor/erase sequences let the
box **overwrite/forge host-terminal content**, including the AgentBox approval-prompt band, to
socially engineer the host-action approval gate.

## Running it

```bash
node security-assessment/pocs/terminal-escape-injection/poc.mjs   # no build needed
```

## Fix directions

- Apply `sanitize()` (or a stricter allow-list) to **every** box-originated string rendered to a
  host TTY: `plan.plan`, `question.question`, option labels/descriptions, session titles — at the
  host render sites (`agent.ts`, `footer.ts`, `sidebar.ts`), not just the OSC-title path.
- Strip/deny the `plan`/`question` content at the trust boundary (relay `/events` ingest or the
  ctl socket) as defense in depth. The type comment claiming `sessionTitle` is "sanitized" is
  currently false — make it true.
