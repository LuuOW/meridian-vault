// vault.ask-meridian.uk — auth screen is one button.
//
// The page fetches its own encrypted blob (./vault.json, same origin,
// anonymous) on load. The user clicks "Sign in with passkey." The browser
// shows the OS-native passkey picker — local platform passkey, USB
// security key, NFC, QR for cross-device. If none resolves, the OS itself
// shows "no passkey available" and the auth attempt simply fails.
//
// On successful unlock: the PRF extension output decrypts the master
// passphrase, which decrypts the vault. The GitHub PAT for writes lives
// inside the vault as a regular secret (GITHUB_PAT). Registration of new
// passkeys happens only AFTER auth, from inside the authed view.

const VAULT_URL = './vault.json'   // served by GitHub Pages alongside this page
const PBKDF2_ITERS = 100_000
const RP_ID = location.hostname
const PRF_SALT_TEXT = 'vault.ask-meridian.uk:prf-v1'

// ── DOM ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id)
const lock = $('lock'), vault = $('vault'), bootstrap = $('bootstrap'), authBadge = $('authBadge')
const passkeyAuthBtn = $('passkeyAuthBtn'), passkeyAuthErr = $('passkeyAuthErr')
const bootPat = $('bootPat'), bootBtn = $('bootBtn'), bootErr = $('bootErr')

const secretsList = $('secretsList'), passkeysList = $('passkeysList'), sshList = $('sshList')
const newBtn = $('newBtn'), addPasskeyBtn = $('addPasskeyBtn'), addSshBtn = $('addSshBtn')
const logoutBtn = $('logoutBtn'), rotatePatBtn = $('rotatePatBtn')

const editDialog = $('editDialog'), editKey = $('editKey'), editValue = $('editValue'), editTitle = $('editTitle'), editSave = $('editSave'), editErr = $('editErr')
const viewDialog = $('viewDialog'), viewTitle = $('viewTitle'), viewValue = $('viewValue'), copyBtn = $('copyBtn'), deleteBtn = $('deleteBtn')
const sshDialog = $('sshDialog'), sshName = $('sshName'), sshKey = $('sshKey'), sshSave = $('sshSave'), sshErr = $('sshErr')

let state = {
  pat: null, passphrase: null, doc: null, secrets: null, remoteSha: null,
  currentEdit: null, currentView: null,
}

// ── b64 helpers ────────────────────────────────────────────────────────
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
function b64ToBuf(s) {
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

// ── Crypto ─────────────────────────────────────────────────────────────
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
  return {
    salt:  bufToB64(salt),
    nonce: bufToB64(nonce),
    tag:   bufToB64(ctTag.slice(ctTag.length - 16)),
    ct:    bufToB64(ctTag.slice(0, ctTag.length - 16)),
    iters: PBKDF2_ITERS,
  }
}

async function aesDecrypt(blob, passphrase) {
  const salt  = b64ToBuf(blob.salt)
  const nonce = b64ToBuf(blob.nonce)
  const tag   = b64ToBuf(blob.tag)
  const ct    = b64ToBuf(blob.ct)
  const combined = new Uint8Array(ct.length + tag.length)
  combined.set(ct, 0); combined.set(tag, ct.length)
  const key = await deriveAesKey(passphrase, salt, blob.iters || PBKDF2_ITERS)
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, combined)
  return new TextDecoder().decode(pt)
}

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

// ── State fetch (anonymous, same-origin) and write (PAT from secrets) ──
async function fetchState() {
  const res = await fetch(`${VAULT_URL}?_=${Date.now()}`, { cache: 'no-store' })
  if (!res.ok) throw new Error(`fetch vault.json: HTTP ${res.status}`)
  return await res.json()
}

async function commitState(doc, message) {
  if (!state.pat) throw new Error('No GITHUB_PAT in vault — add one to enable writes')
  // Refresh sha to avoid 409 conflicts.
  const headRes = await fetch(`https://api.github.com/repos/LuuOW/meridian-vault/contents/pages/vault.json?_=${Date.now()}`, {
    headers: { 'Authorization': 'token ' + state.pat, 'Accept': 'application/vnd.github+json' },
    cache: 'no-store',
  })
  if (headRes.ok) state.remoteSha = (await headRes.json()).sha

  const content = btoa(unescape(encodeURIComponent(JSON.stringify(doc, null, 2))))
  const body = { message, content }
  if (state.remoteSha) body.sha = state.remoteSha
  const res = await fetch('https://api.github.com/repos/LuuOW/meridian-vault/contents/pages/vault.json', {
    method: 'PUT',
    headers: {
      'Authorization': 'token ' + state.pat,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  let data = null
  try { data = await res.json() } catch {}
  if (!res.ok) throw new Error(`commit: HTTP ${res.status}: ${data?.message || res.statusText}`)
  state.remoteSha = data.content?.sha || data.sha
  state.doc = doc
}

// ── WebAuthn ───────────────────────────────────────────────────────────
function prfSalt() {
  const s = new Uint8Array(32)
  s.set(new TextEncoder().encode(PRF_SALT_TEXT))
  return s
}

async function signInWithPasskey() {
  // No allowCredentials — OS-native picker shows local + USB + NFC + QR.
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID,
      timeout: 60_000,
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: prfSalt() } } },
    },
  })
  if (!cred) throw new Error('No credential returned')

  const prfOutput = cred.getClientExtensionResults?.()?.prf?.results?.first
  if (!prfOutput) throw new Error('Authenticator did not return a PRF result')

  const credentialId = bufToB64url(cred.rawId)
  const wrap = (state.doc?.passkeys || []).find(p => p.credentialId === credentialId)
  if (!wrap) throw new Error('This passkey is not registered with this vault')

  return await rawAesDecrypt(wrap.prf_wrapped_passphrase, new Uint8Array(prfOutput))
}

async function registerPasskey(name) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp:   { id: RP_ID, name: 'Meridian Vault' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'vault', displayName: 'Meridian Vault' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestation: 'none',
      timeout: 60_000,
      extensions: { prf: { eval: { first: prfSalt() } } },
    },
  })
  if (!cred) throw new Error('No credential returned')

  let prfOutput = cred.getClientExtensionResults?.()?.prf?.results?.first
  if (!prfOutput) {
    // Some authenticators (notably iCloud Keychain via Safari) only expose
    // PRF on .get(). Do an immediate .get() to extract it.
    const getCred = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: RP_ID,
        timeout: 60_000,
        allowCredentials: [{ type: 'public-key', id: cred.rawId }],
        userVerification: 'preferred',
        extensions: { prf: { eval: { first: prfSalt() } } },
      },
    })
    prfOutput = getCred?.getClientExtensionResults?.()?.prf?.results?.first
    if (!prfOutput) throw new Error('Authenticator does not support the PRF extension')
  }

  return {
    credentialId: bufToB64url(cred.rawId),
    name, alg: 'ES256/EdDSA',
    prfOutput: new Uint8Array(prfOutput),
    createdAt: new Date().toISOString(),
  }
}

// ── State machine ──────────────────────────────────────────────────────
async function init() {
  authBadge.textContent = 'fetching…'
  authBadge.className = 'badge badge-muted'
  try {
    state.doc = await fetchState()
    if (!state.doc?.passkeys?.length) showBootstrap()
    else showLock()
  } catch (e) {
    authBadge.textContent = 'offline'
    authBadge.className = 'badge badge-warn'
    showBootstrap()
    setTimeout(() => alert(`Failed to load vault: ${e.message}`), 0)
  }
}

function showBootstrap() {
  bootstrap.hidden = false; lock.hidden = true; vault.hidden = true
  authBadge.textContent = 'set-up'; authBadge.className = 'badge badge-warn'
  bootPat?.focus()
}

function showLock() {
  bootstrap.hidden = true; lock.hidden = false; vault.hidden = true
  authBadge.textContent = 'locked'; authBadge.className = 'badge badge-warn'
  passkeyAuthBtn.disabled = false
}

function showVault() {
  bootstrap.hidden = true; lock.hidden = true; vault.hidden = false
  authBadge.textContent = 'authed'; authBadge.className = 'badge badge-ok'
  renderSecrets(); renderPasskeys(); renderSshKeys()
}

// ── Bootstrap (first passkey ever) ─────────────────────────────────────
bootBtn?.addEventListener('click', async () => {
  bootErr.hidden = true
  const pat = bootPat.value.trim()
  if (!pat) { bootErr.textContent = 'PAT required'; bootErr.hidden = false; return }
  bootBtn.disabled = true
  bootBtn.textContent = '⏳ encrypting fresh vault…'
  try {
    // Random 256-bit master key, b64u-encoded → used as the "passphrase" string
    // that PBKDF2 derives the AES key from. Effectively unguessable.
    const masterPass = bufToB64url(crypto.getRandomValues(new Uint8Array(32)))

    // Encrypt empty secrets dict with the new master.
    const blob = await aesEncrypt('{}', masterPass)

    // Register passkey with PRF.
    bootBtn.textContent = '⏳ touch authenticator…'
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: RP_ID, name: 'Meridian Vault' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'vault', displayName: 'Meridian Vault' },
      pubKeyCredParams: [{ type:'public-key', alg:-7 }, { type:'public-key', alg:-8 }],
      authenticatorSelection: { residentKey:'preferred', userVerification:'preferred' },
      attestation: 'none', timeout: 60_000,
      extensions: { prf: { eval: { first: prfSalt() } } },
    }})
    if (!cred) throw new Error('No credential')

    // Extract PRF — Safari often emits only on .get().
    let prf = cred.getClientExtensionResults?.()?.prf?.results?.first
    if (!prf) {
      bootBtn.textContent = '⏳ touch again to extract PRF…'
      const g = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: RP_ID, timeout: 60_000,
        allowCredentials: [{ type:'public-key', id: cred.rawId }],
        userVerification: 'preferred',
        extensions: { prf: { eval: { first: prfSalt() } } },
      }})
      prf = g?.getClientExtensionResults?.()?.prf?.results?.first
      if (!prf) throw new Error('Authenticator does not support the PRF extension')
    }

    // Wrap master key under PRF.
    const wrapped = await rawAesEncrypt(masterPass, new Uint8Array(prf))

    // Commit fresh vault.json — overwrites any existing (unrecoverable) blob.
    const newDoc = {
      version: 1, vault: blob,
      passkeys: [{
        credentialId: bufToB64url(cred.rawId),
        name: 'first passkey', alg: 'ES256/EdDSA',
        prf_wrapped_passphrase: wrapped,
        createdAt: new Date().toISOString(),
      }],
      ssh_keys: [],
    }
    bootBtn.textContent = '⏳ committing to GitHub…'
    state.pat = pat
    state.remoteSha = null
    await commitState(newDoc, 'vault: bootstrap with first passkey')

    bootBtn.textContent = '✓ done — reloading…'
    setTimeout(() => location.reload(), 800)
  } catch (e) {
    console.error(e)
    bootErr.textContent = e.message || String(e)
    bootErr.hidden = false
    bootBtn.disabled = false
    bootBtn.textContent = '🔑 Register first passkey'
  }
})

// ── The button ─────────────────────────────────────────────────────────
passkeyAuthBtn.addEventListener('click', async () => {
  passkeyAuthErr.hidden = true
  if (!window.PublicKeyCredential || !navigator.credentials) {
    passkeyAuthErr.textContent = 'WebAuthn not supported in this browser.'
    passkeyAuthErr.hidden = false; return
  }
  try {
    const passphrase = await signInWithPasskey()
    const pt = await aesDecrypt(state.doc.vault, passphrase)
    state.secrets = JSON.parse(pt)
    state.passphrase = passphrase
    state.pat = state.secrets.GITHUB_PAT || null
    showVault()
  } catch (e) {
    if (e.name === 'NotAllowedError') return  // user cancelled — silent
    passkeyAuthErr.textContent = e.message || String(e)
    passkeyAuthErr.hidden = false
  }
})

// ── Authed: secrets ────────────────────────────────────────────────────
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
  editKey.disabled = false; editErr.hidden = true
  editDialog.showModal()
})

editSave.addEventListener('click', async () => {
  editErr.hidden = true
  const key = editKey.value.trim(), value = editValue.value
  if (!key.match(/^[A-Z][A-Z0-9_]{0,63}$/)) {
    editErr.textContent = 'key must be UPPER_SNAKE_CASE'; editErr.hidden = false; return
  }
  state.secrets[key] = value
  if (key === 'GITHUB_PAT') state.pat = value
  try { await persistVault('add ' + key) }
  catch (e) { editErr.textContent = e.message; editErr.hidden = false; return }
  editDialog.close(); renderSecrets()
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
  viewDialog.close(); renderSecrets()
})

async function persistVault(message) {
  const blob = await aesEncrypt(JSON.stringify(state.secrets), state.passphrase)
  const doc = { ...(state.doc || {}), version: 1, vault: blob }
  await commitState(doc, `vault: ${message}`)
}

// ── Authed: passkeys ───────────────────────────────────────────────────
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
      await commitState({ ...state.doc, version: 1 }, 'vault: remove passkey')
      renderPasskeys()
    })
  )
}

addPasskeyBtn.addEventListener('click', async () => {
  const name = prompt('Name this passkey:', 'passkey')
  if (!name) return
  try {
    const reg = await registerPasskey(name)
    const wrapped = await rawAesEncrypt(state.passphrase, reg.prfOutput)
    state.doc = { ...(state.doc || { version: 1 }),
      passkeys: [...(state.doc?.passkeys || []), {
        credentialId: reg.credentialId, name: reg.name, alg: reg.alg,
        prf_wrapped_passphrase: wrapped, createdAt: reg.createdAt,
      }] }
    await commitState(state.doc, `vault: register passkey "${name}"`)
    renderPasskeys()
  } catch (e) { alert('Passkey registration failed: ' + (e.message || e)) }
})

// ── Authed: ssh keys (CLI metadata) ────────────────────────────────────
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
  let fp
  try {
    const blob = b64ToBuf(parts[1])
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', blob))
    fp = 'SHA256:' + bufToB64(hash).replace(/=+$/, '')
  } catch (e) { sshErr.textContent = 'malformed key: ' + e.message; sshErr.hidden = false; return }
  state.doc = { ...(state.doc || { version: 1 }),
    ssh_keys: [...(state.doc?.ssh_keys || []), { name, type: 'ssh-ed25519', pubkey, fingerprint: fp, createdAt: new Date().toISOString() }]
  }
  try { await commitState(state.doc, `vault: add ssh key "${name}"`) }
  catch (e) { sshErr.textContent = e.message; sshErr.hidden = false; return }
  sshDialog.close(); renderSshKeys()
})

// ── Session ────────────────────────────────────────────────────────────
logoutBtn?.addEventListener('click', () => {
  state.passphrase = null; state.secrets = null; state.pat = null
  showLock()
})

rotatePatBtn?.addEventListener('click', async () => {
  const next = prompt('New GitHub PAT (will replace GITHUB_PAT in the vault):')
  if (!next) return
  state.secrets.GITHUB_PAT = next.trim()
  state.pat = next.trim()
  try { await persistVault('rotate GITHUB_PAT'); alert('PAT rotated.') }
  catch (e) { alert('Rotate failed: ' + e.message) }
})

// ── Utils ──────────────────────────────────────────────────────────────
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }
function fmt(iso) { return iso ? new Date(iso).toISOString().slice(0, 16).replace('T', ' ') : '—' }

init()
