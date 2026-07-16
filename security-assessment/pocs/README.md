# AgentBox security assessment — proof-of-concept exploits

One directory per confirmed **medium+** finding. Each has a `README.md` (the finding, exact code
cites, what the PoC proves, fix directions), the PoC itself, and a captured `evidence.txt`. See
[`../REPORT.md`](../REPORT.md) for the full assessment.

## Prerequisites

```bash
# from the repo root, once:
pnpm install
pnpm --filter @agentbox/relay... build
pnpm --filter @agentbox/sandbox-cloud... build
pnpm --filter @agentbox/core build
```

The two docker PoCs also build a tiny local stand-in image (the registry is blocked in the
assessment sandbox); on a normal host you can point them at the real `agentbox/box:dev`.

## Index

| Dir | Sev | Runnable | What it proves |
|---|---|---|---|
| [relay-git-rpc-rce](relay-git-rpc-rce) | Critical | `node poc.mjs` | Box bearer token → host RCE + secret exfil via `git.fetch`/`git.push`, no prompt (real relay) |
| [docker-git-hook-escape](docker-git-hook-escape) | Critical | `bash poc.sh` | Box writes host `.git/hooks` → host RCE on a routine host git op |
| [cross-box-propagate-injection](cross-box-propagate-injection) | High | `node poc.mjs` | Box-controlled dir name → command execution in a *different* box (real sync transport) |
| [hub-auth-bypass](hub-auth-bypass) | High | `node poc.mjs` | Forged cookie passes the hetzner/vercel hub `/api/v1` gate (real better-auth) |
| [e2b-vnc-unauth](e2b-vnc-unauth) | High | walkthrough | Public tokenless preview URL fronts an unauthenticated VNC desktop |
| [terminal-escape-injection](terminal-escape-injection) | Medium | `node poc.mjs` | Box status text → raw OSC-52/CSI into the host TTY |
| [docker-dangerous-caps](docker-dangerous-caps) | Medium | `bash poc.sh` | Box has `CAP_SYS_ADMIN`, seccomp off, privileged `mount` |
| [host-only-branch-clobber](host-only-branch-clobber) | Medium | `node poc.mjs` | Box force-overwrites host `main`, no gate (real refspec builders) |
| [credentials-fanout-poisoning](credentials-fanout-poisoning) | Medium | `node poc.mjs` | Box overwrites the shared host credential backup (real relay `/events`) |

All PoCs are self-contained, use throwaway temp dirs, and clean up after themselves. They print
`VULNERABLE` (or `ISOLATION WEAKENED`) and exit non-zero if the issue does **not** reproduce.
