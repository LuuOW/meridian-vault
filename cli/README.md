# vault-cli

CLI access to the vault. Two auth paths to GitHub:

- **HTTPS + PAT**: `export VAULT_PAT=github_pat_...`
- **SSH**: standard `git@github.com:LuuOW/vault-state.git` access via your SSH key

Both fetch the same `vault.json` from the private state repo. Decryption
happens locally with the master passphrase (typed on stdin or from
`~/.vault/passphrase`, mode 0600).

## Usage (planned)

```bash
vault-cli get STRIPE_SECRET_KEY            # prints to stdout
vault-cli set NEW_KEY                      # reads value from stdin
vault-cli list                             # all keys
vault-cli delete OLD_KEY
```

## Status

Not implemented yet — track at https://github.com/LuuOW/meridian-vault/issues.
For now, fetch via the GitHub API and decrypt with any AES-GCM tool that
matches the blob shape (`{salt, nonce, tag, ct, iters}`, PBKDF2-SHA256
@ 100k iterations).
