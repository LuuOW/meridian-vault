// vault.ask-meridian.uk — Cloudflare Worker (edge build).
// Replaces the legacy server.mjs file vault. Storage is a single KV namespace
// (binding name VAULT_KV) holding:
//
//   vault.enc.json          — AES-256-GCM blob of the secrets dict (as before).
//   session:<id>            — opaque session token, 12 h TTL.
//   sshkey:<fingerprint>    — registered SSH public keys (Ed25519 only).
//   sshchal:<id>            — outstanding SSH challenges, 90 s TTL.
//   passkey:<credId-b64u>   — registered WebAuthn credentials (ES256 + EdDSA).
//   passkey_chal:<id-b64u>  — outstanding WebAuthn challenges, 5 min TTL.
//
// Auth methods:
//   1. Bearer token (env VAULT_TOKEN) — bootstrap + headless clients.
//   2. SSH key challenge-response (Ed25519). Sign a vault-issued nonce with
//      `ssh-keygen -Y sign -n vault.ask-meridian.uk -f ~/.ssh/id_ed25519`,
//      submit the armored signature back. Verified at the edge using
//      Web Crypto's Ed25519 primitive.
//   3. WebAuthn passkeys (ES256 / EdDSA). Browser-native, no shared secret.
//      Verified by hand on top of WebCrypto + a tiny CBOR decoder (no deps).
//   4. Cookie session (vault_sess) once any of the above succeeds.
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

// ── WebAuthn / passkeys (ES256 + EdDSA, pure WebCrypto) ────────────────────
// No SimpleWebAuthn dep — for a single-user vault, hand-rolling against
// WebCrypto is shorter than the bundle plumbing would be. Only ES256
// (alg -7, EC2 P-256) and EdDSA (alg -8, OKP Ed25519) are supported; those
// cover essentially every platform/cross-platform passkey shipped today.
const RP_ID   = 'vault.ask-meridian.uk';
const RP_NAME = 'Meridian Vault';
const ORIGIN  = 'https://vault.ask-meridian.uk';
const PASSKEY_USER_ID = 'vault-user';   // single-tenant, fixed handle

// b64url decoder helper. (b64urlFromBytes is already defined near the top.)
function bytesFromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return bytesFromB64(s);
}

// Minimal CBOR decoder. Handles the major types used by COSE_Key +
// attestationObject: 0=uint, 1=negint, 2=bytestring, 3=textstring, 4=array,
// 5=map. Indefinite-length items aren't emitted by WebAuthn so we don't
// implement them. Returns plain JS values, with maps as Map() so integer
// keys (used by COSE) round-trip cleanly.
class CborReader {
  constructor(bytes) { this.b = bytes; this.p = 0; }
  byte() { return this.b[this.p++]; }
  read(n) { const o = this.b.slice(this.p, this.p + n); this.p += n; return o; }
  argLen(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return this.byte();
    if (ai === 25) { const a = this.byte(), b = this.byte(); return (a << 8) | b; }
    if (ai === 26) { let v = 0; for (let i = 0; i < 4; i++) v = v * 256 + this.byte(); return v; }
    if (ai === 27) { let v = 0; for (let i = 0; i < 8; i++) v = v * 256 + this.byte(); return v; }
    throw new Error('cbor: indefinite-length unsupported');
  }
  next() {
    const initByte = this.byte();
    const major = initByte >> 5;
    const len = this.argLen(initByte & 0x1f);
    switch (major) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: return this.read(len);
      case 3: return new TextDecoder().decode(this.read(len));
      case 4: { const arr = []; for (let i = 0; i < len; i++) arr.push(this.next()); return arr; }
      case 5: { const m = new Map(); for (let i = 0; i < len; i++) { const k = this.next(); m.set(k, this.next()); } return m; }
      default: throw new Error('cbor: major type ' + major + ' unsupported');
    }
  }
}
function cborDecode(bytes) { return new CborReader(bytes).next(); }

// COSE_Key Map → { jwk, alg, importParams, verifyParams }.
function coseToVerifyKey(cose) {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && alg === -7) {
    const x = cose.get(-2), y = cose.get(-3);
    if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error('cose ES256: bad x/y');
    return {
      jwk: { kty: 'EC', crv: 'P-256', x: b64urlFromBytes(x), y: b64urlFromBytes(y), ext: true, key_ops: ['verify'] },
      alg, importParams: { name: 'ECDSA', namedCurve: 'P-256' }, verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
    };
  }
  if (kty === 1 && alg === -8) {
    const x = cose.get(-2);
    if (!x || x.length !== 32) throw new Error('cose EdDSA: bad x');
    return {
      jwk: { kty: 'OKP', crv: 'Ed25519', x: b64urlFromBytes(x), ext: true, key_ops: ['verify'] },
      alg, importParams: { name: 'Ed25519' }, verifyParams: { name: 'Ed25519' },
    };
  }
  throw new Error(`unsupported COSE key (kty=${kty} alg=${alg}); only ES256+EdDSA accepted`);
}

// Authenticator Data binary layout (WebAuthn §6.1):
//   rpIdHash[32] | flags[1] | signCount[4] | [attestedCredData] | [extensions]
function parseAuthData(authData) {
  if (authData.length < 37) throw new Error('authData too short');
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount =
    (authData[33] * 0x1000000) + (authData[34] << 16) + (authData[35] << 8) + authData[36];
  const out = {
    rpIdHash, flags, signCount,
    userPresent:  !!(flags & 0x01),
    userVerified: !!(flags & 0x04),
    hasAttested:  !!(flags & 0x40),
  };
  if (out.hasAttested) {
    if (authData.length < 55) throw new Error('attested cred data missing');
    out.aaguid = authData.slice(37, 53);
    const credIdLen = (authData[53] << 8) | authData[54];
    out.credentialId = authData.slice(55, 55 + credIdLen);
    const r = new CborReader(authData.slice(55 + credIdLen));
    out.credentialPublicKey = r.next();
  }
  return out;
}

// DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) → raw r||s of fieldLen each.
function derEcdsaToRaw(der, fieldLen) {
  if (der[0] !== 0x30) throw new Error('der: not sequence');
  let p = 2;
  if (der[1] & 0x80) p = 2 + (der[1] & 0x7f);
  if (der[p++] !== 0x02) throw new Error('der: not INTEGER r');
  let rlen = der[p++]; let r = der.slice(p, p + rlen); p += rlen;
  if (der[p++] !== 0x02) throw new Error('der: not INTEGER s');
  let slen = der[p++]; let s = der.slice(p, p + slen);
  while (r.length > fieldLen && r[0] === 0) r = r.slice(1);
  while (s.length > fieldLen && s[0] === 0) s = s.slice(1);
  if (r.length > fieldLen || s.length > fieldLen) throw new Error('der: oversized r/s');
  const out = new Uint8Array(2 * fieldLen);
  out.set(r, fieldLen - r.length);
  out.set(s, 2 * fieldLen - s.length);
  return out;
}

async function passkeyRegisterOptions(req, env) {
  if (!(await authed(req, env)))
    return jsonRes({ error: 'unauthorized — sign in (token/ssh) before enrolling a passkey' }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const name = (body.name || 'passkey').slice(0, 64);

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cid = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(16)));
  await env.VAULT_KV.put('passkey_chal:' + cid, JSON.stringify({
    challenge_b64u: b64urlFromBytes(challenge),
    type: 'register', name,
  }), { expirationTtl: 300 });

  const listed = await env.VAULT_KV.list({ prefix: 'passkey:' });
  const excludeCredentials = listed.keys.map(k => ({
    type: 'public-key', id: k.name.slice('passkey:'.length),
  }));

  return jsonRes({
    challenge_id: cid,
    options: {
      challenge: b64urlFromBytes(challenge),
      rp:   { id: RP_ID, name: RP_NAME },
      user: {
        id: b64urlFromBytes(new TextEncoder().encode(PASSKEY_USER_ID)),
        name: 'vault', displayName: 'Meridian Vault',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -8 },   // EdDSA
      ],
      timeout: 60_000,
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestation: 'none',
      excludeCredentials,
    },
  });
}

async function passkeyRegisterVerify(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const cid  = body.challenge_id;
  const cred = body.credential;
  if (!cid || !cred) return jsonRes({ error: 'challenge_id + credential required' }, { status: 400 });

  const chal = await env.VAULT_KV.get('passkey_chal:' + cid, 'json');
  if (!chal || chal.type !== 'register') return jsonRes({ error: 'challenge expired or wrong type' }, { status: 400 });

  let clientData;
  try { clientData = JSON.parse(new TextDecoder().decode(bytesFromB64url(cred.response.clientDataJSON))); }
  catch (e) { return jsonRes({ error: 'bad clientDataJSON: ' + e.message }, { status: 400 }); }
  if (clientData.type !== 'webauthn.create')          return jsonRes({ error: 'wrong clientData type' }, { status: 400 });
  if (clientData.challenge !== chal.challenge_b64u)   return jsonRes({ error: 'challenge mismatch' }, { status: 400 });
  if (clientData.origin !== ORIGIN)                   return jsonRes({ error: 'origin mismatch (got ' + clientData.origin + ')' }, { status: 400 });

  let attest;
  try { attest = cborDecode(bytesFromB64url(cred.response.attestationObject)); }
  catch (e) { return jsonRes({ error: 'bad attestationObject: ' + e.message }, { status: 400 }); }
  const authData = attest.get('authData');
  if (!authData) return jsonRes({ error: 'missing authData' }, { status: 400 });

  let parsed;
  try { parsed = parseAuthData(authData); }
  catch (e) { return jsonRes({ error: 'parse authData: ' + e.message }, { status: 400 }); }
  if (!parsed.userPresent) return jsonRes({ error: 'user-presence flag not set' }, { status: 400 });
  if (!parsed.hasAttested) return jsonRes({ error: 'no attested cred data' }, { status: 400 });

  const expectedRpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(RP_ID)));
  for (let i = 0; i < 32; i++)
    if (expectedRpHash[i] !== parsed.rpIdHash[i]) return jsonRes({ error: 'rpIdHash mismatch' }, { status: 400 });

  let pk;
  try { pk = coseToVerifyKey(parsed.credentialPublicKey); }
  catch (e) { return jsonRes({ error: e.message }, { status: 400 }); }

  // Sanity check: the imported key actually loads via WebCrypto.
  try { await crypto.subtle.importKey('jwk', pk.jwk, pk.importParams, false, ['verify']); }
  catch (e) { return jsonRes({ error: 'importKey failed: ' + e.message }, { status: 400 }); }

  const credIdB64u = b64urlFromBytes(parsed.credentialId);
  await env.VAULT_KV.put('passkey:' + credIdB64u, JSON.stringify({
    name: chal.name, jwk: pk.jwk, alg: pk.alg,
    signCount: parsed.signCount, created_at: new Date().toISOString(),
  }));
  await env.VAULT_KV.delete('passkey_chal:' + cid);
  return jsonRes({ ok: true, credentialId: credIdB64u, name: chal.name });
}

async function passkeyAuthOptions(req, env) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cid = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(16)));
  await env.VAULT_KV.put('passkey_chal:' + cid, JSON.stringify({
    challenge_b64u: b64urlFromBytes(challenge), type: 'auth',
  }), { expirationTtl: 300 });

  const listed = await env.VAULT_KV.list({ prefix: 'passkey:' });
  const allowCredentials = listed.keys.map(k => ({
    type: 'public-key', id: k.name.slice('passkey:'.length),
  }));
  return jsonRes({
    challenge_id: cid,
    options: {
      challenge: b64urlFromBytes(challenge),
      rpId: RP_ID, timeout: 60_000,
      userVerification: 'preferred',
      allowCredentials,
    },
  });
}

async function passkeyAuthVerify(req, env) {
  const body = await req.json().catch(() => ({}));
  const cid  = body.challenge_id;
  const cred = body.credential;
  if (!cid || !cred) return jsonRes({ error: 'challenge_id + credential required' }, { status: 400 });

  const chal = await env.VAULT_KV.get('passkey_chal:' + cid, 'json');
  if (!chal || chal.type !== 'auth') return jsonRes({ error: 'challenge expired or wrong type' }, { status: 400 });

  let clientData;
  try { clientData = JSON.parse(new TextDecoder().decode(bytesFromB64url(cred.response.clientDataJSON))); }
  catch (e) { return jsonRes({ error: 'bad clientDataJSON: ' + e.message }, { status: 400 }); }
  if (clientData.type !== 'webauthn.get')             return jsonRes({ error: 'wrong clientData type' }, { status: 400 });
  if (clientData.challenge !== chal.challenge_b64u)   return jsonRes({ error: 'challenge mismatch' }, { status: 400 });
  if (clientData.origin !== ORIGIN)                   return jsonRes({ error: 'origin mismatch' }, { status: 400 });

  const credId = cred.id;
  const stored = await env.VAULT_KV.get('passkey:' + credId, 'json');
  if (!stored) return jsonRes({ error: 'unknown credential id' }, { status: 401 });

  const authData = bytesFromB64url(cred.response.authenticatorData);
  let parsed;
  try { parsed = parseAuthData(authData); }
  catch (e) { return jsonRes({ error: 'parse authData: ' + e.message }, { status: 400 }); }
  if (!parsed.userPresent) return jsonRes({ error: 'user-presence flag not set' }, { status: 400 });

  const expectedRpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(RP_ID)));
  for (let i = 0; i < 32; i++)
    if (expectedRpHash[i] !== parsed.rpIdHash[i]) return jsonRes({ error: 'rpIdHash mismatch' }, { status: 400 });

  // Sign-counter monotonicity. Some platform authenticators (notably iCloud
  // Keychain / Apple) always emit 0; we accept that case but still detect
  // regressions when the authenticator does maintain a counter.
  if (parsed.signCount !== 0 && parsed.signCount <= stored.signCount)
    return jsonRes({ error: 'signCount regressed (possible cloned authenticator)' }, { status: 400 });

  const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(cred.response.clientDataJSON)));
  const signedData = concat(authData, cdjHash);

  let sigBytes = bytesFromB64url(cred.response.signature);
  let importParams, verifyParams;
  if (stored.alg === -7) {
    sigBytes = derEcdsaToRaw(sigBytes, 32);
    importParams = { name: 'ECDSA', namedCurve: 'P-256' };
    verifyParams = { name: 'ECDSA', hash: 'SHA-256' };
  } else if (stored.alg === -8) {
    importParams = { name: 'Ed25519' };
    verifyParams = { name: 'Ed25519' };
  } else {
    return jsonRes({ error: 'unsupported stored alg ' + stored.alg }, { status: 500 });
  }

  let valid;
  try {
    const cryptoKey = await crypto.subtle.importKey('jwk', stored.jwk, importParams, false, ['verify']);
    valid = await crypto.subtle.verify(verifyParams, cryptoKey, sigBytes, signedData);
  } catch (e) { return jsonRes({ error: 'verify error: ' + e.message }, { status: 500 }); }
  if (!valid) return jsonRes({ error: 'signature invalid' }, { status: 401 });

  stored.signCount = parsed.signCount;
  await env.VAULT_KV.put('passkey:' + credId, JSON.stringify(stored));
  await env.VAULT_KV.delete('passkey_chal:' + cid);
  const sess = await newSession(env);
  return jsonRes({ ok: true, credentialId: credId, name: stored.name }, {
    headers: { 'set-cookie': `vault_sess=${sess}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12*3600}` },
  });
}

async function passkeyList(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const listed = await env.VAULT_KV.list({ prefix: 'passkey:' });
  const keys = [];
  for (const k of listed.keys) {
    const v = await env.VAULT_KV.get(k.name, 'json');
    if (v) keys.push({
      credentialId: k.name.slice('passkey:'.length),
      name: v.name,
      alg: v.alg === -7 ? 'ES256' : v.alg === -8 ? 'EdDSA' : 'alg' + v.alg,
      created_at: v.created_at,
    });
  }
  return jsonRes({ keys });
}

async function passkeyDelete(req, env) {
  if (!(await authed(req, env))) return jsonRes({ error: 'unauthorized' }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  if (!body.credentialId) return jsonRes({ error: 'credentialId required' }, { status: 400 });
  await env.VAULT_KV.delete('passkey:' + body.credentialId);
  return jsonRes({ ok: true });
}

async function countPasskeys(env) {
  const listed = await env.VAULT_KV.list({ prefix: 'passkey:' });
  return listed.keys.length;
}

// ── Main router ────────────────────────────────────────────────────────────
async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  const stat = serveStatic(path);
  if (stat) return stat;

  if (path === '/health') {
    return jsonRes({ ok: true, name: 'meridian-vault', edge: 'cloudflare-workers',
                     auth: ['bearer', 'ssh-ed25519', 'webauthn-passkey', 'session'] });
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
    return jsonRes({ authed: ok, passkeys: await countPasskeys(env) });
  }

  // SSH-key auth ─────────────────────────────────────────────────────────────
  if (path === '/ssh/register'  && req.method === 'POST') return await sshRegister(req, env);
  if (path === '/ssh/list'      && req.method === 'GET')  return await sshList(req, env);
  if (path === '/ssh/delete'    && req.method === 'POST') return await sshDelete(req, env);
  if (path === '/ssh/challenge' && req.method === 'POST') return await sshChallenge(req, env);
  if (path === '/ssh/verify'    && req.method === 'POST') return await sshVerify(req, env);

  // WebAuthn passkey auth ──────────────────────────────────────────────────
  if (path === '/passkey/register-options' && req.method === 'POST') return await passkeyRegisterOptions(req, env);
  if (path === '/passkey/register-verify'  && req.method === 'POST') return await passkeyRegisterVerify(req, env);
  if (path === '/passkey/auth-options'     && req.method === 'POST') return await passkeyAuthOptions(req, env);
  if (path === '/passkey/auth-verify'      && req.method === 'POST') return await passkeyAuthVerify(req, env);
  if (path === '/passkey/list'             && req.method === 'GET')  return await passkeyList(req, env);
  if (path === '/passkey/delete'           && req.method === 'POST') return await passkeyDelete(req, env);

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
