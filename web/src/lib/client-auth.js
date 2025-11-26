import sodiumModule from 'libsodium-wrappers-sumo';
import { initWSClient } from './ws-rpc-client';
import { loadDeviceSecretB64, saveDeviceSecretB64, loadClientStaticKeyB64, saveClientStaticKeyB64 } from './key-store';

let SODIUM, deviceKey = null, clientStaticKey = null, sessionToken = null, CLOCK_SKEW = 0, tokenExp = 0;
let sessionExpired = false;

// Logging
const log = (...args) => console.log('%c[CLIENT-AUTH]%c', 'color:#3498db;font-weight:bold', 'color:inherit', ...args);
const logErr = (...args) => console.error('%c[CLIENT-AUTH ERR]%c', 'color:#e74c3c;font-weight:bold', 'color:inherit', ...args);

export async function bootstrapClient(apiBase) {
  log('Initializing client authentication...', { apiBase });
  SODIUM = await sodiumModule.ready ? sodiumModule : await sodiumModule;
  const S = sodiumModule;
  const enc = new TextEncoder();
  log('libsodium loaded');

  const b64STD = (u8) => S.to_base64(u8, S.base64_variants.ORIGINAL);
  const fromAnyB64 = (s) => {
    const v = S.base64_variants;
    for (const variant of [v.URLSAFE_NO_PADDING, v.URLSAFE, v.ORIGINAL_NO_PADDING, v.ORIGINAL]) {
      try { return S.from_base64(s, variant); } catch {}
    }
    let norm = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (norm.length % 4)) % 4;
    norm += '='.repeat(pad);
    return S.from_base64(norm, v.ORIGINAL);
  };

  // load or create device key (IndexedDB)
  const raw = await loadDeviceSecretB64();
  if (raw) {
    log('Loading existing device key from IndexedDB');
    const sk = fromAnyB64(raw);
    const pk = (typeof S.crypto_sign_ed25519_sk_to_pk === 'function')
      ? S.crypto_sign_ed25519_sk_to_pk(sk)
      : (sk.length === 64 ? new Uint8Array(sk.subarray(32, 64)) : S.crypto_sign_seed_keypair(sk).publicKey);
    deviceKey = { sk, pk };
    log('Device key loaded, public key:', b64STD(pk).substring(0, 16) + '...');
  } else {
    log('Generating new device keypair');
    const kp = S.crypto_sign_keypair();
    deviceKey = { sk: kp.privateKey, pk: kp.publicKey };
    const b64 = S.to_base64(deviceKey.sk, S.base64_variants.URLSAFE_NO_PADDING);
    const saved = await saveDeviceSecretB64(b64);
    log('New device key generated and stored in IndexedDB:', saved ? 'OK' : 'FAILED (using in-memory key)');
  }

  // Load or create X25519 static key for ECDH with agent
  const rawStatic = await loadClientStaticKeyB64();
  if (rawStatic) {
    log('Loading existing client static key (X25519) from IndexedDB');
    const sk = fromAnyB64(rawStatic);
    const pk = S.crypto_scalarmult_base(sk);
    clientStaticKey = { sk, pk };
    log('Client static key loaded, public key:', b64STD(pk).substring(0, 16) + '...');
  } else {
    log('Generating new X25519 static keypair for ECDH');
    const kp = S.crypto_box_keypair(); // X25519 keypair
    clientStaticKey = { sk: kp.privateKey, pk: kp.publicKey };
    const b64 = S.to_base64(clientStaticKey.sk, S.base64_variants.URLSAFE_NO_PADDING);
    const saved = await saveClientStaticKeyB64(b64);
    log('X25519 static key generated and stored:', saved ? 'OK' : 'FAILED (using in-memory key)');
  }

  log('Requesting registration challenge from server...');
  const chall = await fetch(`${apiBase}/client/register_challenge`).then(r => r.json());
  log('Challenge received:', { nonce: chall.server_nonce?.substring(0, 16) + '...', server_ts: chall.ts });
  const nowSec = Math.floor(Date.now() / 1000);
  if (Number.isFinite(chall.ts)) {
    CLOCK_SKEW = chall.ts - nowSec;
    log('Clock skew detected:', CLOCK_SKEW, 'seconds');
  }

  const ctx = enc.encode('viberra-client-reg-v1');
  const nonce = fromAnyB64(chall.server_nonce);
  const ts = Math.floor(Date.now() / 1000);
  const msg = new Uint8Array(ctx.length + nonce.length + deviceKey.pk.length + String(ts).length);
  let off = 0;
  msg.set(ctx, off); off += ctx.length;
  msg.set(nonce, off); off += nonce.length;
  msg.set(deviceKey.pk, off); off += deviceKey.pk.length;
  msg.set(enc.encode(String(ts)), off);
  const sig = S.crypto_sign_detached(msg, deviceKey.sk);
  log('Signature generated, sending registration request...');

  const res = await fetch(`${apiBase}/client/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      device_pub: b64STD(deviceKey.pk),
      server_nonce: chall.server_nonce,
      ts,
      sig: b64STD(sig),
      platform: 'web',
      label: 'Web Console'
    })
  });
  if (!res.ok) {
    logErr('Registration failed:', res.status, await res.text());
    throw new Error(`register failed: ${res.status}`);
  }
  const reg = await res.json();
  sessionToken = reg.session_token;
  tokenExp = reg.exp || 0;
  log('Registration successful!', {
    device_id: reg.device_id,
    fingerprint: reg.fingerprint,
    token_expires: new Date(tokenExp * 1000).toISOString()
  });

  // Initialize WebSocket client after successful registration
  try {
    log('Initializing WebSocket RPC client...');

    // Warm up session with authorized ping and allow time for replication
    try { await authFetch(apiBase, 'health'); } catch {}
    await new Promise(r => setTimeout(r, 400));

    await initWSClient(apiBase, deviceKey, sessionToken);
    log('WebSocket RPC client connected');
  } catch (err) {
    // 4401 on first attempt is normal, auto-reconnect will follow
    const msg = String(err?.message || '');
    if (msg.includes('4401')) {
      console.warn('[CLIENT-AUTH] WS not ready yet (4401); will reconnect in background');
    } else {
      logErr('Failed to initialize WebSocket client:', err);
    }
    // Continue anyway - app can fall back to HTTP
  }
}

export async function authFetch(apiBase, path, opts = {}) {
  // 1. If session already marked as expired - immediately throw SESSION_EXPIRED
  if (sessionExpired) {
    throw new Error('SESSION_EXPIRED');
  }

  // 2. If token is missing - treat it as expired session
  if (!sessionToken) {
    logErr('authFetch called without sessionToken, treating as SESSION_EXPIRED');
    sessionExpired = true;
    throw new Error('SESSION_EXPIRED');
  }

  const S = sodiumModule;
  const enc = new TextEncoder();

  // Renew ~every 5 minutes or if less than 60s remaining
  const skewNow = Math.floor(Date.now() / 1000) + CLOCK_SKEW;
  if (tokenExp && (tokenExp - skewNow) < 60) {
    log('Token expiring soon, renewing...', { expires_in: tokenExp - skewNow });
    await renewToken(apiBase);
  }

  log('→', opts.method || 'GET', path);

  const u = new URL(path, apiBase);
  const ts = Math.floor(Date.now() / 1000) + CLOCK_SKEW;
  const th = await crypto.subtle.digest('SHA-256', enc.encode(sessionToken));
  const ctx = enc.encode('viberra-client-dpop-v1');
  const method = enc.encode((opts.method || 'GET').toUpperCase());
  const dpath = enc.encode(u.pathname);
  const tsBuf = enc.encode(String(ts));

  const body = new Uint8Array(ctx.length + method.length + dpath.length + tsBuf.length + 32);
  let off = 0;
  body.set(ctx, off); off += ctx.length;
  body.set(method, off); off += method.length;
  body.set(dpath, off); off += dpath.length;
  body.set(tsBuf, off); off += tsBuf.length;
  body.set(new Uint8Array(th), off);

  const sig = S.crypto_sign_detached(body, deviceKey.sk);
  const headers = Object.assign({}, opts.headers || {}, {
    'authorization': `Bearer ${sessionToken}`,
    'x-auth-ts': String(ts),
    'x-auth-sig': S.to_base64(sig, S.base64_variants.ORIGINAL),
    'content-type': (opts.headers && opts.headers['content-type']) || 'application/json'
  });

  const response = await fetch(u.toString(), { ...opts, headers });

  // Better error diagnostics for 401 responses
  if (!response.ok && response.status === 401) {
    const errorText = await response.text();
    logErr('401 Unauthorized:', {
      path,
      method: opts.method || 'GET',
      error: errorText,
      tokenExp,
      currentTime: skewNow
    });
    throw new Error(`401 Unauthorized: ${errorText || 'invalid token or signature'}`);
  }

  return response;
}

async function renewToken(apiBase) {
  log('Renewing token...');
  const S = sodiumModule; const enc = new TextEncoder();
  const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(sessionToken)));
  const ctx = enc.encode('viberra-client-renew-v1');
  const ts = Math.floor(Date.now() / 1000) + CLOCK_SKEW;

  // Form device_id from public key hash (same as in register)
  const deviceIdBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', deviceKey.pk));
  const deviceId = Array.from(deviceIdBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');

  const m = new Uint8Array(ctx.length + deviceId.length + String(ts).length + tokenHash.length);
  let off = 0;
  m.set(ctx, off); off += ctx.length;
  m.set(enc.encode(deviceId), off); off += deviceId.length;
  m.set(enc.encode(String(ts)), off); off += String(ts).length;
  m.set(tokenHash, off);

  const sig = S.crypto_sign_detached(m, deviceKey.sk);
  const res = await fetch(`${apiBase}/client/token/renew`, {
    method: 'POST',
    headers: { 'authorization': `Bearer ${sessionToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ ts, sig: S.to_base64(sig, S.base64_variants.ORIGINAL) })
  });
  if (!res.ok) {
    logErr('Token renewal failed:', res.status);

    // If renewal returns 401, the session is dead
    if (res.status === 401) {
      sessionExpired = true;
      sessionToken = null;
      tokenExp = 0;

      // Close WebSocket client to stop reconnection attempts
      const { closeWSClient } = await import('./ws-rpc-client');
      closeWSClient();

      logErr('Session expired (401 on renew). Application needs to reload.');
      throw new Error('SESSION_EXPIRED');
    }

    return;
  }
  const j = await res.json();
  sessionToken = j.session_token; tokenExp = j.exp || 0;
  log('Token renewed successfully, new expiration:', new Date(tokenExp * 1000).toISOString());

  // Update WebSocket client with new token if it exists
  const { getWSClient } = await import('./ws-rpc-client');
  const wsClient = getWSClient();
  if (wsClient) {
    wsClient.sessionToken = sessionToken;
    log('Updated WebSocket client with new token');
  }
}

export function getDeviceKey() {
  return deviceKey;
}

// Export client static key (X25519) for pairing
export function getClientStaticKey() {
  return clientStaticKey;
}

// Export session token
export function getSessionToken() {
  return sessionToken;
}

// Export clock skew
export function getClockSkew() {
  return CLOCK_SKEW;
}

// Export sodium module for crypto operations
export function getSodium() {
  return SODIUM;
}

// Export session expiration status
export function isSessionExpired() {
  return sessionExpired;
}
