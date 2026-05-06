// vault.ask-meridian.uk — pure-client GitHub-Pages vault.
//
// State lives in a private GitHub repo (LuuOW/vault-state) as a single
// vault.json file. Reads/writes go through the GitHub Contents API using a
// fine-grained PAT scoped to that one repo. All crypto happens locally:
// AES-256-GCM with a key derived from a master passphrase via PBKDF2-SHA256.
//
// Auth in the UI is passkey-only. WebAuthn .get() is invoked WITHOUT
// allowCredentials, so the browser shows the full native picker (local
// platform passkey, USB key, NFC, QR code for cross-device). Each passkey
// wraps the master passphrase via the prf extension — Touch ID / Hello /
// modern security keys all support it.
//
// Two persistent stores in this browser:
//   localStorage["vault.pat"]       — fine-grained GitHub PAT (read/write)
//   localStorage["vault.state.repo"]— defaults to LuuOW/vault-state
// Master passphrase is NEVER persisted — only held in memory after unlock.

// ── Config ─────────────────────────────────────────────────────────────
const STATE_OWNER = 'LuuOW'
const STATE_REPO  = 'vault-state'
const STATE_PATH  = 'vault.json'
const PBKDF2_ITERS = 100_000
const RP_ID = location.hostname  // 'vault.ask-meridian.uk' in prod, 'localhost' in dev

// ── DOM ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id)
const setup = $('setup'), lock = $('lock'), vault = $('vault')
const authBadge = $('authBadge')

// Setup wizard
const setupPat = $('setupPat'), setupPatNext = $('setupPatNext')
const setupPassphrase = $('setupPassphrase'), setupPassNext = $('setupPassNext')
const setupPasskeyName = $('setupPasskeyName'), setupPasskeyBtn = $('setupPasskeyBtn')
const setupErr = $('setupErr'), setupPasskeyErr = $('setupPasskeyErr')
const step1 = $('step1'), step2 = $('step2'), step3 = $('step3')

// Lock screen
const passkeyAuthBtn = $('passkeyAuthBtn'), passkeyAuthErr = $('passkeyAuthErr')
const lockPassphrase = $('lockPassphrase'), lockPassphraseBtn = $('lockPassphraseBtn'), lockPassphraseErr = $('lockPassphraseErr')

// Vault
const secretsList = $('secretsList'), passkeysList = $('passkeysList'), sshList = $('sshList')
const newBtn = $('newBtn'), addPasskeyBtn = $('addPasskeyBtn'), addSshBtn = $('addSshBtn')
const logoutBtn = $('logoutBtn'), rotatePatBtn = $('rotatePatBtn')

// Dialogs
const editDialog = $('editDialog'), editKey = $('editKey'), editValue = $('editValue'), editTitle = $('editTitle'), editSave = $('editSave'), editErr = $('editErr')
const viewDialog = $('viewDialog'), viewTitle = $('viewTitle'), viewValue = $('viewValue'), copyBtn = $('copyBtn'), deleteBtn = $('deleteBtn')
const sshDialog = $('sshDialog'), sshName = $('sshName'), sshKey = $('sshKey'), sshSave = $('sshSave'), sshErr = $('sshErr')
const passphraseDialog = $('passphraseDialog'), passphraseInput = $('passphraseInput'), passphraseOk = $('passphraseOk'), passphraseErr = $('passphraseErr'), passphrasePrompt = $('passphrasePrompt')

// In-memory session state — NEVER persisted.
let state = {
  pat:        null,   // GitHub PAT (kept in localStorage, copied here on load)
  passphrase: null,   // master passphrase (in-memory only)
  remoteSha:  null,   // last seen sha of vault.json on GitHub (for optimistic concurrency)
  doc:        null,   // parsed state file contents
  secrets:    null,   // decrypted secrets dict
  currentEdit: null,
  currentView: null,
}

// ── b64url <-> ArrayBuffer / Uint8Array ────────────────────────────────
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const u8 = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}
function bufToB64url(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64ToBuf(s) {  // standard b64 (the existing vault.enc.json blob uses this)
  const bin = atob(s)
  const u8 = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}
function bufToB64(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i])
  return btoa(s)
}

// ── Crypto: PBKDF2-SHA256 → AES-256-GCM ────────────────────────────────
async function deriveAesKey(passphrase, saltU8, iters = PBKDF2_ITERS) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' }, false, ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltU8, iterations: iters, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  )
}

async function aesEncrypt(plaintextStr, passphrase) {
  const salt  = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key   = await deriveAesKey(passphrase, salt)
  const ctTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintextStr)
  ))
  // WebCrypto returns ct||tag (tag is the trailing 16 bytes). Split it to
  // match the legacy server's blob shape so the existing CLI/edge code can
  // still decrypt round-tripped data.
  const ct  = ctTag.slice(0, ctTag.length - 16)
  const tag = ctTag.slice(ctTag.length - 16)
  return {
    salt:  bufToB64(salt),
    nonce: bufToB64(nonce),
    tag:   bufToB64(tag),
    ct:    bufToB64(ct),
    iters: PBKDF2_ITERS,
  }
}

async function aesDecrypt(blob, passphrase) {
  const salt    = b64ToBuf(blob.salt)
  const nonce   = b64ToBuf(blob.nonce)
  const tag     = b64ToBuf(blob.tag)
  const ct      = b64ToBuf(blob.ct)
  const combined = new Uint8Array(ct.length + tag.length)
  combined.set(ct, 0); combined.set(tag, ct.length)
  const key = await deriveAesKey(passphrase, salt, blob.iters || PBKDF2_ITERS)
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, combined)
  return new TextDecoder().decode(pt)
}

// AES-GCM with a raw 32-byte key (used to wrap the master passphrase under
// the PRF output). No PBKDF2 step — PRF output is already a strong key.
async function rawAesEncrypt(plaintextStr, rawKey32) {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['encrypt'])
  const ctTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintextStr)
  ))
  return {
    nonce: bufToB64url(nonce),
    ct:    bufToB64url(ctTag.slice(0, ctTag.length - 16)),
    tag:   bufToB64url(ctTag.slice(ctTag.length - 16)),
  }
}
async function rawAesDecrypt(blob, rawKey32) {
  const nonce = b64urlToBuf(blob.nonce)
  const ct    = b64urlToBuf(blob.ct)
  const tag   = b64urlToBuf(blob.tag)
  const combined = new Uint8Array(ct.length + tag.length)
  combined.set(ct, 0); combined.set(tag, ct.length)
  const key = await crypto.subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['decrypt'])
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, combined)
  return new TextDecoder().decode(pt)
}

// ── GitHub Contents API ────────────────────────────────────────────────
async function gh(method, path, body) {
  const url = `https://api.github.com/repos/${STATE_OWNER}/${STATE_REPO}/${path}`
  const opts = {
    method,
    headers: {
      'Authorization': 'token ' + state.pat,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  }
  if (body) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(url, opts)
  if (res.status === 404) return { __notFound: true }
  let data = null
  try { data = await res.json() } catch {}
  if (!res.ok) throw new Error(`GitHub ${method} ${res.status}: ${data?.message || res.statusText}`)
  return data
}

async function fetchState() {
  const res = await gh('GET', `contents/${STATE_PATH}`)
  if (res.__notFound) return { remoteSha: null, doc: null }
  // res.content is base64 with newlines
  const json = JSON.parse(atob(res.content.replace(/\n/g, '')))
  return { remoteSha: res.sha, doc: json }
}

async function commitState(doc, message) {
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(doc, null, 2))))
  const body = { message, content }
  if (state.remoteSha) body.sha = state.remoteSha
  const res = await gh('PUT', `contents/${STATE_PATH}`, body)
  state.remoteSha = res.content?.sha || res.sha
  state.doc = doc
  return res
}

// ── WebAuthn ───────────────────────────────────────────────────────────
function webauthnSupported() { return !!(window.PublicKeyCredential && navigator.credentials) }

// Register a new passkey with the prf extension. Returns { credentialId,
// alg, prf_output } so the caller can wrap the master passphrase.
async function registerPasskey(name) {
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const userId    = crypto.getRandomValues(new Uint8Array(16))
  const prfSalt   = new Uint8Array(32) // fixed salt — same one used at .get() time
  prfSalt.set(new TextEncoder().encode('vault.ask-meridian.uk:prf-v1'), 0)

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp:   { id: RP_ID, name: 'Meridian Vault' },
      user: { id: userId, name: 'vault', displayName: 'Meridian Vault' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -8 },   // EdDSA
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestation: 'none',
      timeout: 60_000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  })
  if (!cred) throw new Error('No credential returned')

  // Try to read PRF output from the registration response. Many platforms
  // (most notably iCloud Keychain via Safari) only expose PRF on .get(), not
  // on .create(). We'll handle that by doing an immediate .get() to pull it.
  let prfOutput = cred.getClientExtensionResults?.()?.prf?.results?.first
  if (!prfOutput) {
    // Fallback: do a fresh .get() right after registration to obtain PRF.
    const getCred = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: RP_ID,
        timeout: 60_000,
        allowCredentials: [{ type: 'public-key', id: cred.rawId }],
        userVerification: 'preferred',
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    })
    prfOutput = getCred?.getClientExtensionResults?.()?.prf?.results?.first
    if (!prfOutput) throw new Error("This authenticator doesn't support the PRF extension. Try Touch ID, Windows Hello, or a YubiKey 5+.")
  }

  // Determine alg from attestationObject — for our purposes, name only.
  const alg = 'ES256/EdDSA' // both supported; we don't need precise alg client-side

  return {
    credentialId: bufToB64url(cred.rawId),
    name,
    alg,
    prfSalt: bufToB64url(prfSalt),
    prfOutput: new Uint8Array(prfOutput),
    createdAt: new Date().toISOString(),
  }
}

// Sign in with passkey. Returns the master passphrase if any registered
// passkey's wrap can be opened with the resulting PRF output. Native
// browser picker (Touch ID + QR + NFC + USB) is shown — allowCredentials
// is intentionally omitted.
async function signInWithPasskey() {
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const prfSalt   = new Uint8Array(32)
  prfSalt.set(new TextEncoder().encode('vault.ask-meridian.uk:prf-v1'), 0)

  const cred = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: RP_ID,
      timeout: 60_000,
      userVerification: 'preferred',
      // allowCredentials intentionally omitted — triggers native picker with
      // QR / NFC / USB key options on top of any local passkeys.
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  })
  if (!cred) throw new Error('No credential returned')

  const prfOutput = cred.getClientExtensionResults?.()?.prf?.results?.first
  if (!prfOutput) throw new Error("Authenticator returned no PRF result. Try a different passkey or use the master passphrase fallback.")

  const credentialId = bufToB64url(cred.rawId)
  const wrap = (state.doc?.passkeys || []).find(p => p.credentialId === credentialId)
  if (!wrap) throw new Error('Passkey not registered with this vault.')

  const passphrase = await rawAesDecrypt(wrap.prf_wrapped_passphrase, new Uint8Array(prfOutput))
  return passphrase
}

// ── State machine ──────────────────────────────────────────────────────
async function init() {
  state.pat = localStorage.getItem('vault.pat')
  if (!state.pat) return showSetup()

  authBadge.textContent = 'fetching state…'
  authBadge.className = 'badge badge-muted'
  try {
    const { remoteSha, doc } = await fetchState()
    state.remoteSha = remoteSha
    state.doc = doc
    if (!doc || !doc.vault?.ct) {
      // Repo file is missing or empty — treat as fresh setup.
      return showSetup({ patAlreadySet: true })
    }
    // Always go to lock screen if we have a vault doc — never disable the
    // passkey button. WebAuthn .get() with allowCredentials omitted shows
    // the native picker (Touch ID + USB key + NFC + QR cross-device) even
    // when nothing's registered locally for this origin.
    return showLock()
  } catch (e) {
    authBadge.textContent = 'offline'
    authBadge.className = 'badge badge-warn'
    alert(`Failed to load vault state: ${e.message}\n\nIf the PAT is wrong, click "Rotate GitHub PAT" inside the vault — or open dev tools and clear localStorage.`)
    showLock()
  }
}

function showSetup({ patAlreadySet = false } = {}) {
  setup.hidden = false; lock.hidden = true; vault.hidden = true
  authBadge.textContent = 'setup'; authBadge.className = 'badge badge-warn'
  if (patAlreadySet) {
    step1.hidden = true; step2.hidden = false
    setupPassphrase.focus()
  } else {
    step1.hidden = false; step2.hidden = true; step3.hidden = true
    setupPat.focus()
  }
}

function showLock() {
  setup.hidden = true; lock.hidden = false; vault.hidden = true
  authBadge.textContent = 'locked'
  authBadge.className = 'badge badge-warn'
  passkeyAuthBtn.disabled = false
  passkeyAuthBtn.textContent = '🔑 Sign in with passkey'
}

function showVault() {
  setup.hidden = true; lock.hidden = true; vault.hidden = false
  authBadge.textContent = 'authed'; authBadge.className = 'badge badge-ok'
  renderSecrets(); renderPasskeys(); renderSshKeys()
}

// ── Secrets ────────────────────────────────────────────────────────────
function renderSecrets() {
  const keys = Object.keys(state.secrets || {}).sort()
  if (!keys.length) {
    secretsList.innerHTML = '<li class="empty">No secrets yet — click + new.</li>'
    return
  }
  secretsList.innerHTML = keys.map(k => `<li data-key="${esc(k)}">
    <span class="key">${esc(k)}</span>
    <span class="meta">${state.secrets[k].length}b</span>
  </li>`).join('')
  secretsList.querySelectorAll('li').forEach(li =>
    li.addEventListener('click', () => viewSecret(li.dataset.key))
  )
}

function viewSecret(key) {
  state.currentView = key
  viewTitle.textContent = key
  viewValue.textContent = state.secrets[key]
  viewDialog.showModal()
}

newBtn.addEventListener('click', () => {
  state.currentEdit = null
  editTitle.textContent = 'New secret'
  editKey.value = ''; editValue.value = ''
  editKey.disabled = false
  editErr.hidden = true
  editDialog.showModal()
})

editSave.addEventListener('click', async () => {
  editErr.hidden = true
  const key = editKey.value.trim(), value = editValue.value
  if (!key.match(/^[A-Z][A-Z0-9_]{0,63}$/)) {
    editErr.textContent = 'key must be UPPER_SNAKE_CASE'; editErr.hidden = false; return
  }
  state.secrets[key] = value
  try { await persistVault('add ' + key) }
  catch (e) { editErr.textContent = e.message; editErr.hidden = false; return }
  editDialog.close()
  renderSecrets()
})

copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(viewValue.textContent)
  copyBtn.textContent = 'Copied!'
  setTimeout(() => { copyBtn.textContent = 'Copy' }, 900)
})

deleteBtn.addEventListener('click', async () => {
  if (!confirm(`Delete ${state.currentView}? This cannot be undone.`)) return
  delete state.secrets[state.currentView]
  await persistVault('delete ' + state.currentView)
  viewDialog.close()
  renderSecrets()
})

// Re-encrypt secrets and commit.
async function persistVault(message) {
  const blob = await aesEncrypt(JSON.stringify(state.secrets), state.passphrase)
  const doc = { ...(state.doc || {}), version: 1, vault: blob }
  await commitState(doc, `vault: ${message}`)
}

// ── Passkeys ───────────────────────────────────────────────────────────
function renderPasskeys() {
  const pks = state.doc?.passkeys || []
  if (!pks.length) {
    passkeysList.innerHTML = '<li class="empty">No passkeys yet — click + register passkey.</li>'
    return
  }
  passkeysList.innerHTML = pks.map(p => `<li data-cid="${esc(p.credentialId)}">
    <span class="key">${esc(p.name)}</span>
    <span class="meta">${esc(p.alg)} · ${fmt(p.createdAt)}</span>
  </li>`).join('')
  passkeysList.querySelectorAll('li').forEach(li =>
    li.addEventListener('click', async () => {
      if (!confirm(`Remove passkey "${li.querySelector('.key').textContent}"?`)) return
      state.doc.passkeys = (state.doc.passkeys || []).filter(p => p.credentialId !== li.dataset.cid)
      const doc = { ...state.doc, version: 1 }
      await commitState(doc, 'vault: remove passkey')
      renderPasskeys()
    })
  )
}

addPasskeyBtn.addEventListener('click', async () => {
  if (!webauthnSupported()) { alert('WebAuthn not supported in this browser.'); return }
  const name = prompt('Name this passkey:', 'passkey')
  if (!name) return
  try {
    const reg = await registerPasskey(name)
    // Wrap the in-memory passphrase under the PRF output.
    const wrapped = await rawAesEncrypt(state.passphrase, reg.prfOutput)
    const newPasskey = {
      credentialId: reg.credentialId,
      name: reg.name,
      alg: reg.alg,
      prfSalt: reg.prfSalt,
      prf_wrapped_passphrase: wrapped,
      createdAt: reg.createdAt,
    }
    state.doc = { ...(state.doc || { version: 1 }), passkeys: [ ...(state.doc?.passkeys || []), newPasskey ] }
    await commitState(state.doc, `vault: register passkey "${name}"`)
    renderPasskeys()
  } catch (e) {
    alert('Passkey registration failed: ' + (e.message || e))
  }
})

// ── SSH keys (CLI metadata, not used for browser auth) ─────────────────
function renderSshKeys() {
  const keys = state.doc?.ssh_keys || []
  if (!keys.length) {
    sshList.innerHTML = '<li class="empty">No SSH keys yet — click + add SSH key.</li>'
    return
  }
  sshList.innerHTML = keys.map(k => `<li data-fp="${esc(k.fingerprint)}">
    <span class="key">${esc(k.name)}</span>
    <span class="meta">${esc(k.fingerprint)}</span>
  </li>`).join('')
  sshList.querySelectorAll('li').forEach(li =>
    li.addEventListener('click', async () => {
      if (!confirm(`Remove SSH key ${li.dataset.fp}?`)) return
      state.doc.ssh_keys = (state.doc.ssh_keys || []).filter(k => k.fingerprint !== li.dataset.fp)
      await commitState(state.doc, 'vault: remove ssh key')
      renderSshKeys()
    })
  )
}

addSshBtn.addEventListener('click', () => {
  sshName.value = ''; sshKey.value = ''; sshErr.hidden = true
  sshDialog.showModal()
})

sshSave.addEventListener('click', async () => {
  sshErr.hidden = true
  const name = sshName.value.trim(), pubkey = sshKey.value.trim()
  if (!name || !pubkey) { sshErr.textContent = 'name and key required'; sshErr.hidden = false; return }
  const parts = pubkey.split(/\s+/)
  if (parts[0] !== 'ssh-ed25519') { sshErr.textContent = 'only ssh-ed25519 supported'; sshErr.hidden = false; return }
  // Compute SHA-256 fingerprint.
  let fp
  try {
    const blob = b64ToBuf(parts[1])
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', blob))
    fp = 'SHA256:' + bufToB64(hash).replace(/=+$/, '')
  } catch (e) { sshErr.textContent = 'malformed key: ' + e.message; sshErr.hidden = false; return }

  state.doc = { ...(state.doc || { version: 1 }),
    ssh_keys: [ ...(state.doc?.ssh_keys || []), { name, type: 'ssh-ed25519', pubkey, fingerprint: fp, createdAt: new Date().toISOString() } ]
  }
  try { await commitState(state.doc, `vault: add ssh key "${name}"`) }
  catch (e) { sshErr.textContent = e.message; sshErr.hidden = false; return }
  sshDialog.close()
  renderSshKeys()
})

// ── Setup wizard ───────────────────────────────────────────────────────
setupPatNext.addEventListener('click', async () => {
  setupErr.hidden = true
  const pat = setupPat.value.trim()
  if (!pat) return
  // Verify the PAT can read the state repo (or 404 if file doesn't exist).
  state.pat = pat
  try {
    const { remoteSha, doc } = await fetchState()
    state.remoteSha = remoteSha
    state.doc = doc
    localStorage.setItem('vault.pat', pat)
    setupPat.value = ''
    step1.hidden = true
    if (doc?.vault?.ct) {
      // Existing vault — proceed straight to passphrase entry.
      step2.hidden = false
      setupPassphrase.focus()
    } else {
      // Empty repo — proceed to passphrase entry; we'll initialise on save.
      step2.hidden = false
      setupPassphrase.focus()
    }
  } catch (e) {
    state.pat = null
    setupErr.textContent = `PAT validation failed: ${e.message}`
    setupErr.hidden = false
  }
})

setupPassNext.addEventListener('click', async () => {
  setupErr.hidden = true
  const passphrase = setupPassphrase.value
  if (passphrase.length < 16) {
    setupErr.textContent = 'passphrase must be ≥16 chars'; setupErr.hidden = false; return
  }
  if (state.doc?.vault?.ct) {
    // Existing vault — verify passphrase decrypts.
    try {
      const pt = await aesDecrypt(state.doc.vault, passphrase)
      state.secrets = JSON.parse(pt)
      state.passphrase = passphrase
    } catch {
      setupErr.textContent = 'passphrase did not decrypt the existing vault'; setupErr.hidden = false; return
    }
  } else {
    // Empty vault — initialise.
    state.secrets = {}
    state.passphrase = passphrase
    const blob = await aesEncrypt(JSON.stringify(state.secrets), passphrase)
    state.doc = { version: 1, vault: blob, passkeys: [], ssh_keys: [] }
    try { await commitState(state.doc, 'vault: initial encryption') }
    catch (e) { setupErr.textContent = e.message; setupErr.hidden = false; return }
  }
  setupPassphrase.value = ''
  step2.hidden = true; step3.hidden = false
  setupPasskeyName.focus()
})

setupPasskeyBtn.addEventListener('click', async () => {
  setupPasskeyErr.hidden = true
  const name = setupPasskeyName.value.trim()
  if (!name) { setupPasskeyErr.textContent = 'name required'; setupPasskeyErr.hidden = false; return }
  try {
    const reg = await registerPasskey(name)
    const wrapped = await rawAesEncrypt(state.passphrase, reg.prfOutput)
    state.doc = {
      ...state.doc, version: 1,
      passkeys: [ ...(state.doc?.passkeys || []), {
        credentialId: reg.credentialId, name: reg.name, alg: reg.alg,
        prfSalt: reg.prfSalt, prf_wrapped_passphrase: wrapped,
        createdAt: reg.createdAt,
      }],
    }
    await commitState(state.doc, `vault: register passkey "${name}"`)
    showVault()
  } catch (e) {
    setupPasskeyErr.textContent = e.message || String(e)
    setupPasskeyErr.hidden = false
  }
})

// ── Lock screen ────────────────────────────────────────────────────────
passkeyAuthBtn.addEventListener('click', async () => {
  passkeyAuthErr.hidden = true
  if (!webauthnSupported()) { passkeyAuthErr.textContent = 'WebAuthn not supported.'; passkeyAuthErr.hidden = false; return }
  try {
    const passphrase = await signInWithPasskey()
    const pt = await aesDecrypt(state.doc.vault, passphrase)
    state.secrets = JSON.parse(pt)
    state.passphrase = passphrase
    showVault()
  } catch (e) {
    passkeyAuthErr.textContent = e.message || String(e)
    passkeyAuthErr.hidden = false
  }
})

lockPassphraseBtn.addEventListener('click', async () => {
  lockPassphraseErr.hidden = true
  const passphrase = lockPassphrase.value
  if (!passphrase) return
  try {
    const pt = await aesDecrypt(state.doc.vault, passphrase)
    state.secrets = JSON.parse(pt)
    state.passphrase = passphrase
    lockPassphrase.value = ''
    showVault()
  } catch {
    lockPassphraseErr.textContent = 'passphrase did not decrypt vault'
    lockPassphraseErr.hidden = false
  }
})

// ── Session controls ───────────────────────────────────────────────────
logoutBtn.addEventListener('click', () => {
  state.passphrase = null
  state.secrets    = null
  showLock()
})

rotatePatBtn.addEventListener('click', () => {
  const next = prompt('New fine-grained PAT (Contents: read & write on vault-state):')
  if (!next) return
  localStorage.setItem('vault.pat', next.trim())
  state.pat = next.trim()
  alert('PAT rotated. Reloading.')
  location.reload()
})

// ── Utils ──────────────────────────────────────────────────────────────
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }
function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ')
}

init()
