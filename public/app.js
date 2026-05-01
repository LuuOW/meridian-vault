// vault frontend — token + passkey unlock, secret CRUD, passkey enroll/delete.

const $ = id => document.getElementById(id)
const lock        = $('lock')
const vault       = $('vault')
const authBadge   = $('authBadge')
const tokenForm   = $('tokenForm')
const tokenInput  = $('tokenInput')
const lockErr     = $('lockErr')
const passkeyAuthBtn = $('passkeyAuthBtn')

const secretsList   = $('secretsList')
const passkeysList  = $('passkeysList')
const newBtn        = $('newBtn')
const enrollBtn     = $('enrollBtn')
const logoutBtn     = $('logoutBtn')

const editDialog = $('editDialog')
const editForm   = $('editForm')
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
  // Lock screen is the safe default render — show it before fetching status,
  // so even if /auth/status fails the user has a usable lock UI.
  try { lock.hidden = false; vault.hidden = true } catch {}

  try {
    const s = await fetchJSON('/auth/status')
    if (s.authed) {
      authBadge.textContent = 'authed' + (s.passkeys ? ' · ' + s.passkeys + ' passkey' + (s.passkeys === 1 ? '' : 's') : '')
      authBadge.className   = 'badge badge-ok'
      lock.hidden = true; vault.hidden = false
      loadSecrets(); loadPasskeys()
      passkeyAuthBtn.hidden = !s.passkeys
    } else {
      authBadge.textContent = 'locked'
      authBadge.className   = 'badge badge-warn'
      lock.hidden = false; vault.hidden = true
      const list = await fetch('/passkey/auth-options', { method: 'GET' }).catch(() => null)
      passkeyAuthBtn.hidden = !list || !list.ok
    }
  } catch (e) {
    authBadge.textContent = 'offline'
    authBadge.className   = 'badge badge-warn'
    // Even on /auth/status failure, keep the lock screen visible.
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

passkeyAuthBtn.addEventListener('click', async () => {
  lockErr.hidden = true
  try {
    const opts = await fetchJSON('/passkey/auth-options')
    const res = await navigator.credentials.get({
      publicKey: deserializeAuthOptions(opts),
    })
    await fetchJSON('/passkey/auth-verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ response: serializeCredential(res) }),
    })
    refreshAuth()
  } catch (err) {
    lockErr.textContent = err.message || String(err)
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

// PASSKEYS --------------------------------------------------------------
async function loadPasskeys() {
  try {
    const { credentials } = await fetchJSON('/passkey/list')
    if (!credentials.length) {
      passkeysList.innerHTML = '<li class="empty">No passkeys enrolled — token-only mode.</li>'
      return
    }
    passkeysList.innerHTML = credentials
      .map(c => `<li data-id="${esc(c.id)}">
        <span class="key">${esc(c.label || 'passkey')}</span>
        <span class="meta">${esc(c.id)} · ${fmt(c.created_at)}</span>
      </li>`)
      .join('')
    passkeysList.querySelectorAll('li').forEach(li =>
      li.addEventListener('click', async () => {
        if (!confirm(`Delete passkey ${li.dataset.id}?`)) return
        await fetchJSON('/passkey/delete', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id_prefix: li.dataset.id }),
        })
        loadPasskeys()
      })
    )
  } catch (e) {
    passkeysList.innerHTML = `<li class="empty err">${esc(e.message)}</li>`
  }
}

enrollBtn.addEventListener('click', async () => {
  try {
    const opts = await fetchJSON('/passkey/register-options')
    const cred = await navigator.credentials.create({
      publicKey: deserializeRegOptions(opts),
    })
    const label = prompt('Label for this passkey:', 'this device')
    await fetchJSON('/passkey/register-verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ response: serializeCredential(cred), label: label || 'passkey' }),
    })
    loadPasskeys(); refreshAuth()
  } catch (e) {
    alert('Enrollment failed: ' + (e.message || e))
  }
})

// WebAuthn helpers ------------------------------------------------------
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const buf = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf.buffer
}
function bufToB64url(buf) {
  let bin = ''
  const u8 = new Uint8Array(buf)
  for (const b of u8) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function deserializeRegOptions(o) {
  return {
    ...o,
    challenge: b64urlToBuf(o.challenge),
    user: { ...o.user, id: b64urlToBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: b64urlToBuf(c.id) })),
  }
}
function deserializeAuthOptions(o) {
  return {
    ...o,
    challenge: b64urlToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: b64urlToBuf(c.id) })),
  }
}
function serializeCredential(c) {
  const r = c.response
  const out = {
    id: c.id, rawId: bufToB64url(c.rawId), type: c.type,
    response: {},
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    authenticatorAttachment: c.authenticatorAttachment || null,
  }
  for (const f of ['attestationObject', 'authenticatorData', 'clientDataJSON', 'signature', 'userHandle']) {
    if (r[f]) out.response[f] = bufToB64url(r[f])
  }
  if (r.getTransports) out.response.transports = r.getTransports()
  return out
}

// utils ----------------------------------------------------------------
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }
function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ')
}

refreshAuth()
