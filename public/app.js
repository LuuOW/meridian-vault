// vault frontend — three sign-in paths (passkey, token, SSH-from-CLI),
// plus secrets / passkey / SSH-key management once authed.

const $ = id => document.getElementById(id)
const lock         = $('lock')
const vault        = $('vault')
const authBadge    = $('authBadge')
const tokenForm    = $('tokenForm')
const tokenInput   = $('tokenInput')
const lockErr      = $('lockErr')
const passkeyAuthBtn = $('passkeyAuthBtn')
const passkeyAuthErr = $('passkeyAuthErr')

const secretsList   = $('secretsList')
const passkeysList  = $('passkeysList')
const addPasskeyBtn = $('addPasskeyBtn')
const sshList       = $('sshList')
const newBtn        = $('newBtn')
const addSshBtn     = $('addSshBtn')
const logoutBtn     = $('logoutBtn')

const editDialog = $('editDialog')
const editKey    = $('editKey')
const editValue  = $('editValue')
const editTitle  = $('editTitle')
const editSave   = $('editSave')
const editErr    = $('editErr')

const viewDialog = $('viewDialog')
const viewTitle  = $('viewTitle')
const viewValue  = $('viewValue')
const copyBtn    = $('copyBtn')
const deleteBtn  = $('deleteBtn')

const sshDialog = $('sshDialog')
const sshName   = $('sshName')
const sshKey    = $('sshKey')
const sshSave   = $('sshSave')
const sshErr    = $('sshErr')

let currentEditKey = null
let currentViewKey = null

const fetchJSON = async (url, opts = {}) => {
  const res = await fetch(url, { credentials: 'same-origin', ...opts })
  let body = null
  try { body = await res.json() } catch {}
  if (!res.ok) throw new Error(body?.error || `HTTP ${res.status}`)
  return body
}

async function refreshAuth() {
  try { lock.hidden = false; vault.hidden = true } catch {}
  try {
    const s = await fetchJSON('/auth/status')
    if (s.authed) {
      authBadge.textContent = 'authed'
      authBadge.className   = 'badge badge-ok'
      lock.hidden = true; vault.hidden = false
      loadSecrets(); loadPasskeys(); loadSshKeys()
    } else {
      authBadge.textContent = 'locked'
      authBadge.className   = 'badge badge-warn'
      lock.hidden = false; vault.hidden = true
    }
  } catch {
    authBadge.textContent = 'offline'
    authBadge.className   = 'badge badge-warn'
    lock.hidden = false; vault.hidden = true
  }
}

tokenForm.addEventListener('submit', async (e) => {
  e.preventDefault()
  lockErr.hidden = true
  try {
    await fetchJSON('/auth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: tokenInput.value }),
    })
    tokenInput.value = ''
    refreshAuth()
  } catch (err) {
    lockErr.textContent = err.message
    lockErr.hidden = false
  }
})

logoutBtn.addEventListener('click', async () => {
  await fetchJSON('/auth/logout', { method: 'POST' }).catch(()=>{})
  refreshAuth()
})

// SECRETS ---------------------------------------------------------------
async function loadSecrets() {
  try {
    const { keys } = await fetchJSON('/secrets')
    if (!keys.length) {
      secretsList.innerHTML = '<li class="empty">No secrets yet — click + new.</li>'
      return
    }
    secretsList.innerHTML = keys
      .sort((a, b) => a.key.localeCompare(b.key))
      .map(k => `<li data-key="${esc(k.key)}">
        <span class="key">${esc(k.key)}</span>
        <span class="meta">${k.length}b · ${fmt(k.updated_at)}</span>
      </li>`)
      .join('')
    secretsList.querySelectorAll('li').forEach(li =>
      li.addEventListener('click', () => viewSecret(li.dataset.key))
    )
  } catch (e) {
    secretsList.innerHTML = `<li class="empty err">${esc(e.message)}</li>`
  }
}

newBtn.addEventListener('click', () => {
  currentEditKey = null
  editTitle.textContent = 'New secret'
  editKey.value = ''; editValue.value = ''
  editKey.disabled = false
  editErr.hidden = true
  editDialog.showModal()
})

editSave.addEventListener('click', async () => {
  editErr.hidden = true
  const key   = editKey.value.trim()
  const value = editValue.value
  try {
    await fetchJSON('/secrets/' + encodeURIComponent(key), {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ value }),
    })
    editDialog.close()
    loadSecrets()
  } catch (e) {
    editErr.textContent = e.message
    editErr.hidden = false
  }
})

async function viewSecret(key) {
  try {
    const { value, updated_at } = await fetchJSON('/secrets/' + encodeURIComponent(key))
    currentViewKey = key
    viewTitle.textContent = key + (updated_at ? ' · updated ' + fmt(updated_at) : '')
    viewValue.textContent = value
    viewDialog.showModal()
  } catch (e) {
    alert(e.message)
  }
}

copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(viewValue.textContent)
  copyBtn.textContent = 'Copied!'
  setTimeout(() => { copyBtn.textContent = 'Copy' }, 900)
})

deleteBtn.addEventListener('click', async () => {
  if (!confirm(`Delete ${currentViewKey}? This cannot be undone.`)) return
  await fetchJSON('/secrets/' + encodeURIComponent(currentViewKey), { method: 'DELETE' })
  viewDialog.close()
  loadSecrets()
})

// SSH KEYS --------------------------------------------------------------
async function loadSshKeys() {
  try {
    const { keys } = await fetchJSON('/ssh/list')
    if (!keys.length) {
      sshList.innerHTML = '<li class="empty">No SSH keys registered yet — click + add SSH key.</li>'
      return
    }
    sshList.innerHTML = keys
      .map(k => `<li data-fp="${esc(k.fingerprint)}">
        <span class="key">${esc(k.name || 'unnamed')}</span>
        <span class="meta">${esc(k.fingerprint)} · ${fmt(k.created_at)}</span>
      </li>`)
      .join('')
    sshList.querySelectorAll('li').forEach(li =>
      li.addEventListener('click', async () => {
        if (!confirm(`Remove SSH key ${li.dataset.fp}?`)) return
        await fetchJSON('/ssh/delete', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ fingerprint: li.dataset.fp }),
        })
        loadSshKeys()
      })
    )
  } catch (e) {
    sshList.innerHTML = `<li class="empty err">${esc(e.message)}</li>`
  }
}

addSshBtn.addEventListener('click', () => {
  sshName.value = ''; sshKey.value = ''
  sshErr.hidden = true
  sshDialog.showModal()
})

sshSave.addEventListener('click', async () => {
  sshErr.hidden = true
  const name = sshName.value.trim()
  const key  = sshKey.value.trim()
  if (!name || !key) {
    sshErr.textContent = 'name and key required'
    sshErr.hidden = false
    return
  }
  try {
    await fetchJSON('/ssh/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, key }),
    })
    sshDialog.close()
    loadSshKeys()
  } catch (e) {
    sshErr.textContent = e.message
    sshErr.hidden = false
  }
})

// PASSKEYS --------------------------------------------------------------
// b64url <-> ArrayBuffer for the WebAuthn JS API.
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const buf = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf.buffer
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function loadPasskeys() {
  if (!passkeysList) return
  try {
    const { keys } = await fetchJSON('/passkey/list')
    if (!keys.length) {
      passkeysList.innerHTML = '<li class="empty">No passkeys yet — click + register passkey.</li>'
      return
    }
    passkeysList.innerHTML = keys
      .map(k => `<li data-cid="${esc(k.credentialId)}">
        <span class="key">${esc(k.name)}</span>
        <span class="meta">${esc(k.alg)} · ${fmt(k.created_at)}</span>
      </li>`)
      .join('')
    passkeysList.querySelectorAll('li').forEach(li =>
      li.addEventListener('click', async () => {
        if (!confirm(`Remove passkey "${li.querySelector('.key').textContent}"?`)) return
        await fetchJSON('/passkey/delete', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ credentialId: li.dataset.cid }),
        })
        loadPasskeys()
      })
    )
  } catch (e) {
    passkeysList.innerHTML = `<li class="empty err">${esc(e.message)}</li>`
  }
}

if (addPasskeyBtn) addPasskeyBtn.addEventListener('click', async () => {
  if (!('credentials' in navigator) || !window.PublicKeyCredential) {
    alert('Passkeys are not supported in this browser.')
    return
  }
  const name = prompt('Name this passkey (e.g. "macbook touch id"):', 'passkey')
  if (!name) return
  try {
    const { challenge_id, options } = await fetchJSON('/passkey/register-options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name }),
    })
    options.challenge = b64urlToBuf(options.challenge)
    options.user.id   = b64urlToBuf(options.user.id)
    if (options.excludeCredentials)
      for (const c of options.excludeCredentials) c.id = b64urlToBuf(c.id)
    const cred = await navigator.credentials.create({ publicKey: options })
    if (!cred) throw new Error('No credential returned')
    await fetchJSON('/passkey/register-verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        challenge_id,
        credential: {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON:    bufToB64url(cred.response.clientDataJSON),
            attestationObject: bufToB64url(cred.response.attestationObject),
          },
        },
      }),
    })
    loadPasskeys()
  } catch (e) {
    alert('Passkey registration failed: ' + (e.message || e))
  }
})

if (passkeyAuthBtn) passkeyAuthBtn.addEventListener('click', async () => {
  passkeyAuthErr.hidden = true
  if (!('credentials' in navigator) || !window.PublicKeyCredential) {
    passkeyAuthErr.textContent = 'Passkeys not supported in this browser.'
    passkeyAuthErr.hidden = false
    return
  }
  try {
    const { challenge_id, options } = await fetchJSON('/passkey/auth-options', { method: 'POST' })
    options.challenge = b64urlToBuf(options.challenge)
    if (!options.allowCredentials || !options.allowCredentials.length)
      throw new Error('No passkeys registered yet — unlock with token first, then enrol one.')
    for (const c of options.allowCredentials) c.id = b64urlToBuf(c.id)
    const cred = await navigator.credentials.get({ publicKey: options })
    if (!cred) throw new Error('No credential returned')
    await fetchJSON('/passkey/auth-verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        challenge_id,
        credential: {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON:    bufToB64url(cred.response.clientDataJSON),
            authenticatorData: bufToB64url(cred.response.authenticatorData),
            signature:         bufToB64url(cred.response.signature),
            userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
          },
        },
      }),
    })
    refreshAuth()
  } catch (e) {
    passkeyAuthErr.textContent = e.message || String(e)
    passkeyAuthErr.hidden = false
  }
})

// utils ----------------------------------------------------------------
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }
function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ')
}

refreshAuth()
