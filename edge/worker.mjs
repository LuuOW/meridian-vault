// vault.ask-meridian.uk — Cloudflare Worker (edge build).
// Replaces the legacy server.mjs file vault. Storage is a single KV namespace
// (binding name VAULT_KV) holding:
//
//   vault.enc.json          — AES-256-GCM blob of the secrets dict (as before).
//   session:<id>            — opaque session token, 12 h TTL.
//   sshkey:<fingerprint>    — registered SSH public keys (Ed25519 only).
//   sshchal:<id>            — outstanding challenges, 90 s TTL.
//
// Auth methods:
//   1. Bearer token (env VAULT_TOKEN) — bootstrap + headless clients.
//   2. SSH key challenge-response (Ed25519). Sign a vault-issued nonce with
//      `ssh-keygen -Y sign -n vault.ask-meridian.uk -f ~/.ssh/id_ed25519`,
//      submit the armored signature back. Verified at the edge using
//      Web Crypto's Ed25519 primitive.
//   3. Cookie session (vault_sess) once either of the above succeeds.
//
// PBKDF2 iterations are 100 000 because Workers Web Crypto caps at that
// (legacy file vault used 200 000; the migrate-to-edge step re-encrypted).

const FILES = __FILES_JSON__;

// ── Tiny utilities ─────────────────────────────────────────────────────────
function bytesFromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64FromBytes(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64urlFromBytes(bytes) {
  return b64FromBytes(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function constantEqStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function parseCookies(s) {
  const out = {};
  if (!s) return out;
  for (const part of s.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    out[k] = decodeURIComponent(rest.join('='));
  }
  return out;
}
function jsonRes(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8', ...(init.headers || {}) },
  });
}

// SSH wire-format helpers ────────────────────────────────────────────────────
class SshReader {
  constructor(bytes) { this.b = bytes; this.pos = 0; }
  bytes(n) {
    if (this.pos + n > this.b.length) throw new Error('ssh-reader: short');
    const out = this.b.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u32() {
    if (this.pos + 4 > this.b.length) throw new Error('ssh-reader: short u32');
    const v = ((this.b[this.pos]<<24) | (this.b[this.pos+1]<<16) |
               (this.b[this.pos+2]<<8)  |  this.b[this.pos+3]) >>> 0;
    this.pos += 4;
    return v;
  }
  string() {
    const len = this.u32();
    return this.bytes(len);
  }
}
function sshString(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}
function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
async function sshFingerprint(pubBlob) {
  // SHA256:<base64-no-padding>(SHA256(blob)) — same as `ssh-keygen -lf`.
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', pubBlob));
  return 'SHA256:' + b64FromBytes(h).replace(/=+$/, '');
}

// ── Crypto: AES-256-GCM with PBKDF2 100k key derivation ────────────────────
async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}
async function decryptBlob(blob, passphrase) {
  const salt  = bytesFromB64(blob.salt);
  const nonce = bytesFromB64(blob.nonce);
  const ct    = bytesFromB64(blob.ct);
  const tag   = bytesFromB64(blob.tag);
  const combined = concat(ct, tag);
  const key = await deriveKey(passphrase, salt);
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, combined);
  return new TextDecoder().decode(pt);
}
async function encryptPlaintext(plaintext, passphrase) {
  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const out = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintext),
  ));
  const tag = out.slice(out.length - 16);
  const ct  = out.slice(0, out.length - 16);
  return {
    salt:  b64FromBytes(salt),
    nonce: b64FromBytes(nonce),
    tag:   b64FromBytes(tag),
    ct:    b64FromBytes(ct),
  };
}

// ── KV-backed storage ──────────────────────────────────────────────────────
async function loadVault(env) {
  const blob = await env.VAULT_KV.get('vault.enc.json', 'json');
  if (!blob) return {};
  try {
    return JSON.parse(await decryptBlob(blob, env.VAULT_PASSPHRASE));
  } catch (e) {
    throw new Error('vault decrypt failed: ' + e.message);
  }
}
async function saveVault(env, secrets) {
  const blob = await encryptPlaintext(JSON.stringify(secrets), env.VAULT_PASSPHRASE);
  await env.VAULT_KV.put('vault.enc.json', JSON.stringify(blob));
}
async function newSession(env) {
  const s = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(24)));
  await env.VAULT_KV.put('session:' + s, JSON.stringify({ created: Date.now() }), {
    expirationTtl: 12 * 3600,
  });
  return s;
}
async function checkSession(env, s) {
  if (!s) return false;
  return !!(await env.VAULT_KV.get('session:' + s));
}
async function dropSession(env, s) { if (s) await env.VAULT_KV.delete('session:' + s); }

// ── Auth middleware ────────────────────────────────────────────────────────
async function authed(req, env) {
  const h = req.headers.get('authorization') || '';
  if (h.startsWith('Bearer ')) {
    const t = h.slice(7).trim();
    if (constantEqStr(t, env.VAULT_TOKEN)) return true;
  }
  const cookies = parseCookies(req.headers.get('cookie') || '');
  const sess = cookies.vault_sess || (h.startsWith('Session ') ? h.slice(8).trim() : '');
  return await checkSession(env, sess);
}

// ── Static UI ──────────────────────────────────────────────────────────────
const STATIC_TYPES = {
  '/':           { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js':     { file: 'app.js',     type: 'application/javascript; charset=utf-8' },
  '/style.css':  { file: 'style.css',  type: 'text/css; charset=utf-8' },
};
function serveStatic(path) {
  const meta = STATIC_TYPES[path];
  if (!meta) return null;
  return new Response(bytesFromB64(FILES[meta.file]), {
    status: 200,
    headers: {
      'content-type': meta.type,
      'cache-control': 'no-store, no-cache, must-revalidate',
    },
  });
}

// ── SSH key auth (Ed25519 only) ────────────────────────────────────────────
const SSH_NAMESPACE = 'vault.ask-meridian.uk';

async function sshRegister(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const keyStr = (body.key || '').trim();
  const name   = (body.name || 'unnamed').slice(0, 64);
  if (!keyStr) return jsonRes({ error: 'body.key required (OpenSSH public key, e.g. `ssh-ed25519 AAAA...`)' }, { status: 400 });

  const parts = keyStr.split(/\s+/);
  if (parts.length < 2 || parts[0] !== 'ssh-ed25519')
    return jsonRes({ error: 'only ssh-ed25519 supported in this build' }, { status: 400 });

  let blob;
  try { blob = bytesFromB64(parts[1]); }
  catch { return jsonRes({ error: 'malformed base64 in key' }, { status: 400 }); }

  try {
    const v = new SshReader(blob);
    const algo = new TextDecoder().decode(v.string());
    const rawPub = v.string();
    if (algo !== 'ssh-ed25519' || rawPub.length !== 32)
      throw new Error('not an ed25519 key');
  } catch (e) {
    return jsonRes({ error: 'malformed ssh wire format: ' + e.message }, { status: 400 });
  }

  const fp = await sshFingerprint(blob);
  const meta = {
    name, type: 'ssh-ed25519', pub_b64: parts[1], fingerprint: fp,
    created_at: new Date().toISOString(),
  };
  await env.VAULT_KV.put('sshkey:' + fp, JSON.stringify(meta));
  return jsonRes({ ok: true, fingerprint: fp, name, type: 'ssh-ed25519' });
}

async function sshList(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const list = await env.VAULT_KV.list({ prefix: 'sshkey:' });
  const keys = [];
  for (const k of list.keys) {
    const v = await env.VAULT_KV.get(k.name, 'json');
    if (v) keys.push({ name: v.name, fingerprint: v.fingerprint, type: v.type, created_at: v.created_at });
  }
  return jsonRes({ keys });
}

async function sshDelete(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  if (!body.fingerprint) return jsonRes({ error: 'fingerprint required' }, { status: 400 });
  await env.VAULT_KV.delete('sshkey:' + body.fingerprint);
  return jsonRes({ ok: true });
}

async function sshChallenge(req, env) {
  const body = await req.json().catch(() => ({}));
  const fp = body.fingerprint;
  if (!fp) return jsonRes({ error: 'fingerprint required (e.g. `ssh-keygen -lf ~/.ssh/id_ed25519.pub | awk \'{print $2}\'`)' }, { status: 400 });
  const meta = await env.VAULT_KV.get('sshkey:' + fp, 'json');
  if (!meta) return jsonRes({ error: 'unknown key fingerprint' }, { status: 404 });
  const cid = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(16)));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce_b64  = b64FromBytes(nonceBytes);
  await env.VAULT_KV.put('sshchal:' + cid, JSON.stringify({
    fingerprint: fp, nonce_b64, namespace: SSH_NAMESPACE,
  }), { expirationTtl: 90 });
  return jsonRes({
    challenge_id: cid,
    nonce: nonce_b64,
    namespace: SSH_NAMESPACE,
    sign_with: `printf %s "<nonce>" | ssh-keygen -Y sign -n ${SSH_NAMESPACE} -f ~/.ssh/id_ed25519`,
  });
}

async function sshVerify(req, env) {
  const body = await req.json().catch(() => ({}));
  const cid     = body.challenge_id;
  const sigArmor = body.signature || '';
  if (!cid || !sigArmor) return jsonRes({ error: 'challenge_id + signature required' }, { status: 400 });

  const chal = await env.VAULT_KV.get('sshchal:' + cid, 'json');
  if (!chal) return jsonRes({ error: 'challenge expired or invalid' }, { status: 400 });
  const meta = await env.VAULT_KV.get('sshkey:' + chal.fingerprint, 'json');
  if (!meta) return jsonRes({ error: 'unknown key for this challenge' }, { status: 400 });

  const m = sigArmor.match(/-----BEGIN SSH SIGNATURE-----\s+([\s\S]+?)\s+-----END SSH SIGNATURE-----/);
  if (!m) return jsonRes({ error: 'malformed SSH signature armor' }, { status: 400 });
  let sigBytes;
  try { sigBytes = bytesFromB64(m[1].replace(/\s+/g, '')); }
  catch { return jsonRes({ error: 'malformed signature base64' }, { status: 400 }); }

  let sigType, sigRaw, namespace, hashAlgo;
  try {
    const r = new SshReader(sigBytes);
    if (new TextDecoder().decode(r.bytes(6)) !== 'SSHSIG')
      throw new Error('bad magic');
    if (r.u32() !== 1) throw new Error('unsupported sig version');
    r.string();                                                // publickey blob (we use stored copy)
    namespace = new TextDecoder().decode(r.string());
    r.string();                                                // reserved (empty)
    hashAlgo  = new TextDecoder().decode(r.string());
    const sigInner = r.string();
    const innerR = new SshReader(sigInner);
    sigType = new TextDecoder().decode(innerR.string());
    sigRaw  = innerR.string();
  } catch (e) {
    return jsonRes({ error: 'parse signature: ' + e.message }, { status: 400 });
  }

  if (namespace !== chal.namespace)
    return jsonRes({ error: `namespace mismatch (got ${namespace}, expected ${chal.namespace})` }, { status: 400 });
  if (sigType !== 'ssh-ed25519' || sigRaw.length !== 64)
    return jsonRes({ error: 'unsupported signature type' }, { status: 400 });
  if (hashAlgo !== 'sha256' && hashAlgo !== 'sha512')
    return jsonRes({ error: 'unsupported hash algorithm' }, { status: 400 });

  // The user signed the literal nonce we issued via `ssh-keygen -Y sign`. SSH-SIG
  // hashes the message with the named algorithm and signs the resulting blob.
  const hashName = hashAlgo === 'sha256' ? 'SHA-256' : 'SHA-512';
  const messageBytes = new TextEncoder().encode(chal.nonce_b64);
  const hashed = new Uint8Array(await crypto.subtle.digest(hashName, messageBytes));

  const signedData = concat(
    new TextEncoder().encode('SSHSIG'),
    sshString(new TextEncoder().encode(chal.namespace)),
    sshString(new Uint8Array(0)),
    sshString(new TextEncoder().encode(hashAlgo)),
    sshString(hashed),
  );

  const pubBlob = bytesFromB64(meta.pub_b64);
  let rawPub;
  try {
    const r2 = new SshReader(pubBlob);
    r2.string(); rawPub = r2.string();
  } catch { return jsonRes({ error: 'stored key malformed' }, { status: 500 }); }
  if (rawPub.length !== 32) return jsonRes({ error: 'stored key not ed25519' }, { status: 500 });

  let valid;
  try {
    const cryptoKey = await crypto.subtle.importKey('raw', rawPub, { name: 'Ed25519' }, false, ['verify']);
    valid = await crypto.subtle.verify({ name: 'Ed25519' }, cryptoKey, sigRaw, signedData);
  } catch (e) {
    return jsonRes({ error: 'verify error: ' + e.message }, { status: 500 });
  }
  if (!valid) return jsonRes({ error: 'signature invalid' }, { status: 401 });

  await env.VAULT_KV.delete('sshchal:' + cid);
  const sess = await newSession(env);
  return jsonRes({ ok: true, name: meta.name, fingerprint: meta.fingerprint }, {
    headers: {
      'set-cookie': `vault_sess=${sess}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12*3600}`,
    },
  });
}

// ── Main router ────────────────────────────────────────────────────────────
async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  const stat = serveStatic(path);
  if (stat) return stat;

  if (path === '/health') {
    return jsonRes({ ok: true, name: 'meridian-vault', edge: 'cloudflare-workers',
                     auth: ['bearer', 'ssh-ed25519', 'session'] });
  }

  if (path === '/auth/token' && req.method === 'POST') {
    const body = await req.json().catch(() => ({}));
    if (!constantEqStr(body.token || '', env.VAULT_TOKEN))
      return jsonRes({ error: 'invalid token' }, { status: 401 });
    const sess = await newSession(env);
    return jsonRes({ ok: true }, {
      headers: { 'set-cookie': `vault_sess=${sess}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12*3600}` },
    });
  }
  if (path === '/auth/logout' && req.method === 'POST') {
    const sess = parseCookies(req.headers.get('cookie') || '').vault_sess;
    await dropSession(env, sess);
    return jsonRes({ ok: true }, {
      headers: { 'set-cookie': 'vault_sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' },
    });
  }
  if (path === '/auth/status') {
    const sess = parseCookies(req.headers.get('cookie') || '').vault_sess;
    const ok = await checkSession(env, sess);
    return jsonRes({ authed: ok, passkeys: 0 });
  }

  // SSH-key auth ─────────────────────────────────────────────────────────────
  if (path === '/ssh/register'  && req.method === 'POST') return await sshRegister(req, env);
  if (path === '/ssh/list'      && req.method === 'GET')  return await sshList(req, env);
  if (path === '/ssh/delete'    && req.method === 'POST') return await sshDelete(req, env);
  if (path === '/ssh/challenge' && req.method === 'POST') return await sshChallenge(req, env);
  if (path === '/ssh/verify'    && req.method === 'POST') return await sshVerify(req, env);

  // Passkey endpoints stubbed (the legacy server.mjs implementation depended on
  // SimpleWebAuthn which isn't ported in this round; bearer + ssh is enough).
  if (path.startsWith('/passkey/')) {
    return jsonRes({ error: 'passkey auth not available on edge build; use bearer or ssh' }, { status: 501 });
  }

  // Secrets API
  if (path.startsWith('/secrets')) {
    if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
    if (path === '/secrets' && req.method === 'GET') {
      try {
        const v = await loadVault(env);
        return jsonRes({
          keys: Object.entries(v).map(([k, meta]) => ({
            key: k, updated_at: meta.updated_at || null,
            length: (meta.value || '').length,
          })),
        });
      } catch (e) { return jsonRes({ error: e.message }, { status: 500 }); }
    }
    const m = path.match(/^\/secrets\/([A-Z][A-Z0-9_]{0,63})$/);
    if (m) {
      const key = m[1];
      try {
        const v = await loadVault(env);
        if (req.method === 'GET') {
          const e = v[key];
          if (!e) return jsonRes({ error: 'not found' }, { status: 404 });
          return jsonRes({ key, value: e.value, updated_at: e.updated_at });
        }
        if (req.method === 'PUT') {
          const body = await req.json().catch(() => ({}));
          if (typeof body.value !== 'string') return jsonRes({ error: 'body.value (string) required' }, { status: 400 });
          if (body.value.length > 8192) return jsonRes({ error: 'value too long (max 8192)' }, { status: 400 });
          v[key] = { value: body.value, updated_at: new Date().toISOString() };
          await saveVault(env, v);
          return jsonRes({ ok: true });
        }
        if (req.method === 'DELETE') {
          if (!(key in v)) return jsonRes({ error: 'not found' }, { status: 404 });
          delete v[key];
          await saveVault(env, v);
          return jsonRes({ ok: true });
        }
      } catch (e) { return jsonRes({ error: e.message }, { status: 500 }); }
    }
    if (req.method !== 'GET') return jsonRes({ error: 'method not allowed' }, { status: 405 });
    return jsonRes({ error: 'not found' }, { status: 404 });
  }

  return new Response('not found', { status: 404 });
}

export default {
  async fetch(req, env) {
    try { return await handle(req, env); }
    catch (e) {
      return jsonRes({ error: 'internal: ' + (e.message || e) }, { status: 500 });
    }
  },
};
