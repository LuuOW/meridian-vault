// vault frontend — token unlock (browser) + SSH-key management.
//
// Edge build: passkey endpoints are stubbed at 501. The browser unlock path
// is bearer-token only; SSH-key sign-in happens from a CLI (the lock screen
// shows the snippet). This module handles everything else: secrets CRUD +
// SSH key registration / listing / deletion.

const $ = id => document.getElementById(id)
const lock        = $('lock')
const vault       = $('vault')
const authBadge   = $('authBadge')
const tokenForm   = $('tokenForm')
const tokenInput  = $('tokenInput')
const lockErr     = $('lockErr')

const secretsList   = $('secretsList')
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
      loadSecrets(); loadSshKeys()
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

// utils ----------------------------------------------------------------
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) }
function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ')
}

refreshAuth()
