// vault.ask-meridian.uk — minimal token+passkey-protected secrets vault.
//
// Two auth paths:
//   1. Bearer token (env VAULT_TOKEN) — bootstrap + headless clients
//   2. WebAuthn passkeys — primary UX, enrolled after first token unlock
//
// Storage: AES-256-GCM at rest. Encryption key derived (PBKDF2-SHA256,
// 200k iters) from VAULT_PASSPHRASE. Rotating the passphrase requires a
// re-encrypt pass (not implemented here — single-tenant, single-user
// service for one operator).

import express from 'express'
import { readFileSync, writeFileSync, existsSync, renameSync, mkdirSync } from 'node:fs'
import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync, timingSafeEqual } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DATA_DIR  = join(__dirname, 'data')
const VAULT_F   = join(DATA_DIR, 'vault.enc.json')
const PASSKEYS_F= join(DATA_DIR, 'passkeys.json')
const PORT      = parseInt(process.env.VAULT_PORT || '8003', 10)
const ORIGIN    = process.env.VAULT_ORIGIN || 'https://vault.ask-meridian.uk'
const RP_ID     = new URL(ORIGIN).hostname
const RP_NAME   = 'Meridian Vault'

const VAULT_TOKEN      = process.env.VAULT_TOKEN
const VAULT_PASSPHRASE = process.env.VAULT_PASSPHRASE
if (!VAULT_TOKEN || VAULT_TOKEN.length < 24) {
  console.error('VAULT_TOKEN env var must be set (≥24 chars)')
  process.exit(1)
}
if (!VAULT_PASSPHRASE || VAULT_PASSPHRASE.length < 16) {
  console.error('VAULT_PASSPHRASE env var must be set (≥16 chars)')
  process.exit(1)
}

mkdirSync(DATA_DIR, { recursive: true })

// ── Encryption (AES-256-GCM, salt+nonce per write) ─────────────────────────
function deriveKey(passphrase, salt) {
  return pbkdf2Sync(passphrase, salt, 200_000, 32, 'sha256')
}

function encrypt(plaintext) {
  const salt  = randomBytes(16)
  const nonce = randomBytes(12)
  const key   = deriveKey(VAULT_PASSPHRASE, salt)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return {
    salt:  salt.toString('base64'),
    nonce: nonce.toString('base64'),
    tag:   tag.toString('base64'),
    ct:    ct.toString('base64'),
  }
}

function decrypt(blob) {
  const salt  = Buffer.from(blob.salt,  'base64')
  const nonce = Buffer.from(blob.nonce, 'base64')
  const tag   = Buffer.from(blob.tag,   'base64')
  const ct    = Buffer.from(blob.ct,    'base64')
  const key   = deriveKey(VAULT_PASSPHRASE, salt)
  const dec   = createDecipheriv('aes-256-gcm', key, nonce)
  dec.setAuthTag(tag)
  return Buffer.concat([dec.update(ct), dec.final()]).toString('utf8')
}

function loadVault() {
  if (!existsSync(VAULT_F)) return {}
  try {
    const blob = JSON.parse(readFileSync(VAULT_F, 'utf8'))
    return JSON.parse(decrypt(blob))
  } catch (e) {
    console.error('vault decrypt failed:', e.message)
    throw new Error('vault corrupted or wrong passphrase')
  }
}

function saveVault(secrets) {
  const blob = encrypt(JSON.stringify(secrets))
  const tmp = VAULT_F + '.tmp'
  writeFileSync(tmp, JSON.stringify(blob, null, 2), { mode: 0o600 })
  renameSync(tmp, VAULT_F)
}

// ── Passkey storage ───────────────────────────────────────────────────────
function loadPasskeys() {
  if (!existsSync(PASSKEYS_F)) return { credentials: {}, challenges: {}, sessions: {} }
  try { return JSON.parse(readFileSync(PASSKEYS_F, 'utf8')) }
  catch { return { credentials: {}, challenges: {}, sessions: {} } }
}

function savePasskeys(data) {
  const tmp = PASSKEYS_F + '.tmp'
  writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 })
  renameSync(tmp, PASSKEYS_F)
}

function newSession() {
  const s = randomBytes(24).toString('base64url')
  const data = loadPasskeys()
  data.sessions[s] = { created: Date.now() }
  savePasskeys(data)
  return s
}

function checkSession(s) {
  if (!s) return false
  const data = loadPasskeys()
  const sess = data.sessions[s]
  if (!sess) return false
  // 12 hour session lifetime
  if (Date.now() - sess.created > 12 * 3600 * 1000) {
    delete data.sessions[s]; savePasskeys(data)
    return false
  }
  return true
}

// ── Auth middleware ───────────────────────────────────────────────────────
function constantEqStr(a, b) {
  const A = Buffer.from(a || '')
  const B = Buffer.from(b || '')
  if (A.length !== B.length) return false
  return timingSafeEqual(A, B)
}

function auth(req, res, next) {
  const h = req.headers.authorization || ''
  // Bearer token
  if (h.startsWith('Bearer ')) {
    const t = h.slice(7).trim()
    if (constantEqStr(t, VAULT_TOKEN)) return next()
  }
  // Passkey session
  const sess = req.cookies?.vault_sess || (h.startsWith('Session ') ? h.slice(8).trim() : '')
  if (checkSession(sess)) return next()
  res.status(401).json({ error: 'unauthorized' })
}

// Light cookie parser (no dependency)
function parseCookies(s) {
  const out = {}
  if (!s) return out
  for (const part of s.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    out[k] = decodeURIComponent(rest.join('='))
  }
  return out
}

// ── App ────────────────────────────────────────────────────────────────────
const app = express()
app.use(express.json({ limit: '256kb' }))
app.use((req, _res, next) => { req.cookies = parseCookies(req.headers.cookie); next() })

// Health (no auth)
app.get('/health', (_req, res) => res.json({ ok: true, name: 'meridian-vault' }))

// Frontend
app.get('/', (_req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8')
  res.send(readFileSync(join(__dirname, 'public', 'index.html'), 'utf8'))
})
app.get('/style.css', (_req, res) => {
  res.set('Content-Type', 'text/css; charset=utf-8')
  res.send(readFileSync(join(__dirname, 'public', 'style.css'), 'utf8'))
})
app.get('/app.js', (_req, res) => {
  res.set('Content-Type', 'application/javascript; charset=utf-8')
  res.send(readFileSync(join(__dirname, 'public', 'app.js'), 'utf8'))
})

// ── Token verify (bootstrap) ──────────────────────────────────────────────
app.post('/auth/token', (req, res) => {
  const t = req.body?.token
  if (!constantEqStr(t, VAULT_TOKEN)) return res.status(401).json({ error: 'invalid token' })
  const sess = newSession()
  res.cookie?.()  // noop guard
  res.set('Set-Cookie', `vault_sess=${sess}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12 * 3600}`)
  res.json({ ok: true })
})

app.post('/auth/logout', (req, res) => {
  const sess = req.cookies.vault_sess
  if (sess) {
    const data = loadPasskeys()
    delete data.sessions[sess]; savePasskeys(data)
  }
  res.set('Set-Cookie', 'vault_sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0')
  res.json({ ok: true })
})

app.get('/auth/status', (req, res) => {
  const data = loadPasskeys()
  const ok = checkSession(req.cookies.vault_sess)
  res.json({
    authed:  ok,
    passkeys: Object.values(data.credentials).length,
  })
})

// ── Passkey: registration ─────────────────────────────────────────────────
app.get('/passkey/register-options', auth, async (req, res) => {
  const opts = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID:   RP_ID,
    userID: Buffer.from('vault-operator'),
    userName: 'operator',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  })
  const data = loadPasskeys()
  data.challenges.register = opts.challenge
  savePasskeys(data)
  res.json(opts)
})

app.post('/passkey/register-verify', auth, async (req, res) => {
  const data = loadPasskeys()
  const expected = data.challenges.register
  if (!expected) return res.status(400).json({ error: 'no challenge' })
  try {
    const out = await verifyRegistrationResponse({
      response: req.body.response,
      expectedChallenge: expected,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    })
    if (!out.verified) return res.status(400).json({ error: 'verification failed' })
    const cred = out.registrationInfo.credential
    data.credentials[cred.id] = {
      id:           cred.id,
      publicKey:    Buffer.from(cred.publicKey).toString('base64'),
      counter:      cred.counter,
      transports:   cred.transports || [],
      label:        req.body.label || 'passkey',
      created_at:   new Date().toISOString(),
    }
    delete data.challenges.register
    savePasskeys(data)
    res.json({ ok: true })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ── Passkey: authentication ───────────────────────────────────────────────
app.get('/passkey/auth-options', async (_req, res) => {
  const data = loadPasskeys()
  const allowCredentials = Object.values(data.credentials).map(c => ({
    id: c.id, transports: c.transports,
  }))
  if (!allowCredentials.length) return res.status(400).json({ error: 'no passkeys enrolled' })
  const opts = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: 'preferred',
  })
  data.challenges.auth = opts.challenge
  savePasskeys(data)
  res.json(opts)
})

app.post('/passkey/auth-verify', async (req, res) => {
  const data = loadPasskeys()
  const expected = data.challenges.auth
  if (!expected) return res.status(400).json({ error: 'no challenge' })
  const cred = data.credentials[req.body.response?.id]
  if (!cred) return res.status(400).json({ error: 'unknown credential' })
  try {
    const out = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: expected,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id:        cred.id,
        publicKey: Buffer.from(cred.publicKey, 'base64'),
        counter:   cred.counter,
      },
    })
    if (!out.verified) return res.status(400).json({ error: 'verification failed' })
    cred.counter = out.authenticationInfo.newCounter
    delete data.challenges.auth
    const sess = randomBytes(24).toString('base64url')
    data.sessions[sess] = { created: Date.now(), passkey: cred.id }
    savePasskeys(data)
    res.set('Set-Cookie', `vault_sess=${sess}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12 * 3600}`)
    res.json({ ok: true, label: cred.label })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

app.get('/passkey/list', auth, (_req, res) => {
  const data = loadPasskeys()
  res.json({
    credentials: Object.values(data.credentials).map(c => ({
      id: c.id.slice(0, 12) + '…',
      label: c.label, created_at: c.created_at,
    })),
  })
})

app.post('/passkey/delete', auth, (req, res) => {
  const data = loadPasskeys()
  const { id_prefix } = req.body
  if (!id_prefix) return res.status(400).json({ error: 'id_prefix required' })
  for (const id of Object.keys(data.credentials)) {
    if (id.startsWith(id_prefix.replace(/…$/, ''))) delete data.credentials[id]
  }
  savePasskeys(data)
  res.json({ ok: true })
})

// ── Secrets CRUD ───────────────────────────────────────────────────────────
app.get('/secrets', auth, (_req, res) => {
  try {
    const v = loadVault()
    res.json({
      keys: Object.entries(v).map(([k, meta]) => ({
        key:        k,
        updated_at: meta.updated_at || null,
        length:     (meta.value || '').length,
      })),
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.get('/secrets/:key', auth, (req, res) => {
  try {
    const v = loadVault()
    const e = v[req.params.key]
    if (!e) return res.status(404).json({ error: 'not found' })
    res.json({ key: req.params.key, value: e.value, updated_at: e.updated_at })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.put('/secrets/:key', auth, (req, res) => {
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(req.params.key))
    return res.status(400).json({ error: 'key must be UPPER_SNAKE_CASE' })
  if (typeof req.body?.value !== 'string')
    return res.status(400).json({ error: 'body.value (string) required' })
  if (req.body.value.length > 8192)
    return res.status(400).json({ error: 'value too long (max 8192)' })
  try {
    const v = loadVault()
    v[req.params.key] = { value: req.body.value, updated_at: new Date().toISOString() }
    saveVault(v)
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.delete('/secrets/:key', auth, (req, res) => {
  try {
    const v = loadVault()
    if (!(req.params.key in v)) return res.status(404).json({ error: 'not found' })
    delete v[req.params.key]
    saveVault(v)
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ── Boot ───────────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[vault] listening http://127.0.0.1:${PORT}  (origin=${ORIGIN})`)
})
