# PoC (walkthrough) — E2B box VNC desktop exposed to the internet with no auth

**Severity: High** · Threat-model item #4 (a party other than the box owner controls/reads the
box) · **E2B provider** · No account, token, or box access required.

> This one is cloud-only (it needs a live E2B sandbox and its public `*.e2b.app` domain), which
> this assessment environment cannot reach. It is a **code-grounded walkthrough** with exact
> cites and reproduction steps rather than a runnable script.

## The bug

The in-box VNC launcher falls back to **no authentication** when `vncpasswd` is missing — which
the code notes is exactly the case on E2B's Debian 12 base:

```sh
# packages/sandbox-docker/scripts/agentbox-vnc-start:27-40
# Debian 12 (E2B base) doesn't package vncpasswd at all — tigervnc-tools is
# Ubuntu-only. When vncpasswd is missing, fall back to `-SecurityTypes None`
# and rely on the cloud provider's signed preview URL as the access boundary
VNC_SECURITY_ARGS=(-SecurityTypes VncAuth -PasswordFile "$HOME/.vnc/passwd")
if command -v vncpasswd >/dev/null 2>&1; then
  ...
else
  echo "... starting Xvnc with -SecurityTypes None (preview URL is the access boundary)" >&2
  VNC_SECURITY_ARGS=(-SecurityTypes None)     # <-- no VNC auth on E2B
fi
```

So on E2B the desktop's only "access boundary" is the preview URL. But the E2B preview URL is
**public with no token**, and "signed" is a no-op:

```ts
// packages/sandbox-e2b/src/backend.ts:407-421
async previewUrl(h, port) {
  ...
  return { url: `https://${port}-${h.sandboxId}.${domain}`, token: undefined };   // no token
}
async signedPreviewUrl(h, port) { return this.previewUrl(h, port); }              // no signing
```

And `sandboxId` is **not secret**: it is the hostname of the user's own **public app preview
URL** (`https://8080-<sandboxId>.e2b.app`, the thing you deliberately share to show your app),
and it appears in logs and box records. Anyone who learns it can open
`https://<vncport>-<sandboxId>.e2b.app` and get a full, **unauthenticated** interactive desktop
in the box — read the workspace/project, the staged agent credentials, and drive the agent.

## Reproduction

1. Owner runs an E2B box that exposes its app preview, e.g. `https://8080-<sandboxId>.e2b.app`
   (normal, intended sharing). The `<sandboxId>` is now known to anyone who sees that URL.
2. Attacker opens the box's VNC/noVNC preview URL for the same sandbox id (the VNC/noVNC port,
   e.g. `https://6080-<sandboxId>.e2b.app`). No token is required (`token: undefined`).
3. Xvnc was started with `-SecurityTypes None`, so the VNC server accepts the connection with
   no password → full desktop access to a box the attacker does not own.

(To confirm the no-auth server directly, in an E2B box: `pgrep -a Xvnc` shows the
`-SecurityTypes None` args, and a `vncviewer https://<port>-<id>.e2b.app` connects without a
password.)

## Fix directions

- Never start Xvnc with `-SecurityTypes None`. Generate a random per-box VNC password even when
  `vncpasswd` is unavailable (write the DES/`VncAuth` blob directly, or ship `tigervnc-tools` /
  a small helper in the E2B template), or use an authenticated web-VNC proxy.
- Treat the E2B preview URL as **public** (it is): put an independent auth layer (token/proxy)
  in front of any in-box service that is not meant for the world, rather than relying on the
  URL being unguessable.
- Do not exempt any provider from VNC auth on the assumption that "the preview URL is the access
  boundary" when that URL carries no token.
