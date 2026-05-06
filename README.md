# meridian-vault

Pure-client secrets vault hosted on GitHub Pages, backed by an encrypted
file in a private GitHub repo.

## Architecture

```
┌─────────────────────────────────────────────┐
│ GitHub Pages — vault.ask-meridian.uk        │
│ ─ Static UI (pages/index.html, app.js, css) │
│ ─ AES-256-GCM in WebCrypto                  │
│ ─ Auth: passkey only (native picker:        │
│   Touch ID + USB key + NFC + QR cross-dev)  │
└──────────────┬──────────────────────────────┘
               │ GitHub Contents API
               ▼
┌─────────────────────────────────────────────┐
│ Private repo — LuuOW/vault-state            │
│   vault.json:                               │
│     { vault: { salt, nonce, tag, ct },      │
│       passkeys: [...PRF-wrapped passphrase],│
│       ssh_keys: [...CLI metadata] }         │
└─────────────────────────────────────────────┘
```

## Crypto

The master passphrase derives a 256-bit AES key via PBKDF2-SHA256 at 100 000
iterations. Secrets are stored as one AES-256-GCM blob.

Each registered passkey wraps the master passphrase under a stable secret
derived via the WebAuthn `prf` extension (Touch ID, Windows Hello, YubiKey
5+ all support it). On unlock, the browser does `navigator.credentials.get`
without `allowCredentials` — the native picker offers every authenticator
the user has, including QR for cross-device hybrid transport.

## Repo layout

| Directory | Purpose |
|-----------|---------|
| `pages/` | Static UI deployed to GitHub Pages |
| `cli/`   | Future Node/Python CLI (read-only fetch + decrypt) |

The actual encrypted blob lives in a separate private repo
(`LuuOW/vault-state`) so the UI repo can be public source while the secrets
themselves stay locked down.

## Threat model

The state repo is **public** so the UI is one button — no PAT entry, no
fields. Anonymous fetch returns the ciphertext, the passkey unlocks it,
the GitHub PAT for writes lives inside the encrypted dict (as a regular
secret named `GITHUB_PAT`).

| Attacker has | Can they read secrets? |
|---|---|
| The static UI source (this repo) | No — it's just JavaScript |
| The encrypted blob (`vault-state/vault.json`) | Only if they brute-force the master passphrase against PBKDF2-SHA256 @ 100 000 iters |
| A registered passkey | Only if it supports PRF *and* they have physical access *and* the AES-GCM blob |
| The master passphrase | Yes — fetch ciphertext anonymously, decrypt locally |

The single security boundary is the master passphrase. With a strong one
(16+ random chars), offline brute force is infeasible at PBKDF2 100k iters
on commodity hardware.

If you'd rather have a two-factor model — passphrase AND repo-access — flip
`vault-state` back to private and stash the PAT in localStorage. The UI
still works the same (it'll just send `Authorization: token` on the read).

## Decommissioned

The original Cloudflare Worker (`meridian-vault-proxy`) and its KV namespace
have been removed. See git history for the legacy `edge/worker.mjs` (CF
Worker) and `server.mjs` (Node Express dev server) implementations.
