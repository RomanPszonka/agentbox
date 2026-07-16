# PoC — Control Hub auth bypass (network profile: hetzner/vercel)

**Severity: High** · Threat-model item #3 (Control Hub host action without a valid gate) ·
Affects the **hetzner/vercel "password" profiles**, which bind `0.0.0.0` and are meant to be
remotely reachable. Combines two independent defects.

## The bugs

On the network profiles the hub auto-enables auth (`server.ts:29`
`if (host !== '127.0.0.1') process.env.AGENTBOX_HUB_AUTH ??= 'on'`) and its sole gate for
`/api/v1/*` and the dashboard is, in `apps/hub/proxy.ts`:

```ts
// password (hetzner/vercel): accept the better-auth session cookie.
if (getSessionCookie(request)) return NextResponse.next();   // proxy.ts:48 (/api/v1), :94 (dashboard)
return apiUnauthorized();
```

**(A) Forged-cookie bypass.** `better-auth`'s `getSessionCookie` is an *optimistic presence*
helper — it returns the raw cookie value with **no signature check, no DB lookup, no
expiry/revocation check**. No `/api/v1` handler re-validates the session (they call the backend
directly), so the comment "Session validity is enforced by the handlers" is false. Any
non-empty `better-auth.session_token` cookie passes.

**(B) Open self-registration.** `auth.ts:47` sets `emailAndPassword: { enabled: true }` with no
`disableSignUp` / `requireEmailVerification`, and the `/api/auth/[...all]` route exposes
`POST /api/auth/sign-up/email`. The middleware matcher excludes `/api/auth`, so sign-up is
itself ungated and returns a **valid** session cookie. The env-seeded admin does not disable
public registration.

Either way, an unauthenticated network client drives every mutating route:
`POST /api/v1/boxes/{id}/destroy|start|stop`, `POST /api/v1/boxes/{id}/git/push` (uses the
host's push token), and `POST /api/v1/approvals/{id}/answer {"answer":"y"}` — which **answers
the host-action approval prompt**, defeating the very gate that guards a box's git push / cp /
gh writes. (Bonus: logout/expiry/revocation never take effect, since validity is re-checked
nowhere.)

## What the PoC proves

`poc.mjs` imports the **real pinned `better-auth@1.6.23`** (the hub's own dependency) and runs
the **verbatim** `proxy.ts` password gate against the privileged routes:

```
1. NO cookie:            all routes -> 401
2. FORGED cookie 'x':    getSessionCookie(...) = "x"  ->  destroy / git push / approval answer  -> ALLOW
VULNERABLE -- all 3/3 privileged routes accept a forged cookie with no account.
```

The bypass is demonstrated at the exact deciding dependency (`getSessionCookie`); standing up
the full Next server would only add the handler behind an already-open gate.

## Running it

```bash
pnpm install
node security-assessment/pocs/hub-auth-bypass/poc.mjs
```

## Fix directions

- In the `/api/v1` and dashboard gates, **validate the session** with
  `auth.api.getSession({ headers })` (DB-backed: checks signature, expiry, revocation) instead
  of `getSessionCookie` presence — or add a real per-request check inside each handler.
- Set `disableSignUp: true` (and/or an invite/allow-list) on the network profiles; the operator
  account is env-seeded, so public sign-up is never needed.
- Add ownership/authz on `/api/v1` routes, not just authentication.
- Do not serve the control plane over plain HTTP on `0.0.0.0` without transport security.
