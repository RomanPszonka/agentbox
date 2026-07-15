# PoC — Box → Host RCE via the read-write `.git/` bind mount (docker backend)

**Severity: Critical** · Threat-model item #1 (a box escaping isolation and reaching the host)
· Default backend (`--provider docker`) · No user credential needed, only the box's normal agent.

## The bug

The docker backend bind-mounts each host repo's `.git/` directory into the box
**read-write**, at its identical host path:

```ts
// packages/sandbox-docker/src/create.ts:718-725
// Bind-mount each main repo's `.git/` at its identical absolute host path, RW.
for (const w of gitWorktreeRecords) {
  extraVolumes.push(`${w.hostMainRepo}/.git:${w.hostMainRepo}/.git`);
}
```

There is **no `:ro`**, **no `core.hooksPath` redirect**, and **no filtering** of what the
box may write into that directory. The whole point of the mount is that the box's commits
land in the host's object DB so the host can `git push` them — but the same writable handle
also exposes `.git/hooks/*` and `.git/config`, which are **executable configuration**:

- `.git/hooks/pre-commit`, `post-commit`, `post-checkout`, `post-merge`, `pre-push`,
  `reference-transaction`, … — arbitrary scripts git runs on ordinary operations.
- `.git/config` keys that run programs: `core.fsmonitor`, `core.pager`, `core.editor`,
  `core.sshCommand`, `[alias] x = !cmd`, `[filter] clean/smudge`, `[diff] textconv`, …

The untrusted agent inside the box controls all of them. Git executes them **on the host**
the next time any git command runs in that repo — which is precisely the AgentBox workflow:
the human reviews commits, checks out between boxes, pulls, and pushes on the host (the
tray app even has buttons for `pull`/`push`/`checkout`), and the host CLI/relay itself runs
git in the same repo during box lifecycle.

`safe.directory` does **not** help — the repo is legitimately owned by the host user, so git
raises no "dubious ownership" block. The box is confined to a container, so the *only* reason
it can reach the host at all is this mount; that makes host execution an isolation escape.

## What the PoC proves

`poc.sh` reproduces the mount **verbatim** (`-v $repo/.git:$repo/.git`, RW) with a plain
**unprivileged** container running as **uid 1000** (the box's `vscode` user) — deliberately
using **none** of the extra powers the real box has (`SYS_ADMIN`, `apparmor:unconfined`,
`seccomp:unconfined`). The escape is the mount alone.

1. A host developer (uid 1000) owns a normal git repo.
2. The "box" container plants `.git/hooks/pre-commit` **and** sets `core.fsmonitor` in
   `.git/config` — writing only through the mounted `.git`.
3. The host developer runs routine `git commit` / `git status`.
4. Both payloads execute **on the host** and write a proof marker into the host user's home
   (a path the container never mounted), recording the host's hostname/uname/uid.

```
VULNERABLE -- the box executed code on the HOST. Marker /home/ubuntu/.agentbox_poc_pwned:
     PWNED via .git/hooks/pre-commit
     ran as:   uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
     on host:  vm            <-- host hostname, not the container's "the-box"
     uname:    Linux vm 6.18.5 ...
     PWNED via .git/config core.fsmonitor
     on host: vm
```

See `evidence.txt` for a full captured run.

## Running it

```bash
# 1) Build the stand-in box image (uid-1000 shell). In an environment with a
#    working registry you would instead just use the real agentbox/box:dev.
bash build-image.sh

# 2) Run the PoC
bash poc.sh
```

> Environment note: this repo's CI sandbox blocks the docker registry, so the PoC uses a
> minimal locally-`docker import`ed rootfs as the box stand-in and models the host developer
> as uid 1000. The mount flag, the container's write, and the host-side git execution are
> the real thing; only the box *image* is a stand-in. On a normal host you can reproduce it
> against a real box: `agentbox create`, then from the agent shell
> `printf '#!/bin/sh\ntouch ~/PWNED\n' > <repo>/.git/hooks/post-checkout && chmod +x $_`,
> and run any `git checkout`/`git commit` on the host.

## Fix directions

- Mount `.git` **read-only** and route the box's commits through the host relay (the relay
  already brokers `git push`); or
- Mount only what the box needs (objects + refs) and keep `hooks/` + `config` host-only; or
- Force `core.hooksPath` to an empty/host-controlled dir and refuse to honor a box-written
  `.git/config` for host-side git (e.g. run host git with `-c core.fsmonitor=false
  -c core.hooksPath=/dev/null` and a hardened environment) — defense in depth, not a
  substitute for removing write access to executable config.
