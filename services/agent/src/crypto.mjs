import process from 'node:process';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import { opts, MAX_CONNECTIONS } from './constants.mjs';
import { agentState } from './state.mjs';
import { logW } from './logger.mjs';

export const KEYS_DIR  = process.env.VIBE_KEYS_DIR || path.join(os.homedir(), '.viberra');
export const KEYS_FILE = path.join(KEYS_DIR, 'keys.json');
export const CLIENTS_FILE = path.join(KEYS_DIR, 'clients.json');

export let edSecret = null;   // Buffer(64) — Ed25519 secretKey
export let edPublic = null;   // Buffer(32) — Ed25519 publicKey
export let xSecret  = null;   // Buffer(32) — X25519 secretKey
export let xPublic  = null;   // Buffer(32) — X25519 publicKey
export let fingerprint = '';  // "SHA256:<hex>"

/** Reads/creates keys and saves them to ~/.viberra/keys.json */
export function ensureKeysLoaded() {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  if (fs.existsSync(KEYS_FILE)) {
    const j = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    edSecret = Buffer.from(j.ed25519.secret, 'base64');
    edPublic = Buffer.from(j.ed25519.public, 'base64');
    xSecret  = Buffer.from(j.x25519.secret, 'base64');
    xPublic  = Buffer.from(j.x25519.public, 'base64');
    fingerprint = j.fingerprint || makeFingerprint(edPublic);
    // Load agentId from saved file
    opts.agentId = j.agent_id || crypto.randomUUID();
    return;
  }
  // Create new keypairs
  const edKeypair = sodium.crypto_sign_keypair();  // Ed25519
  const xKeypair = sodium.crypto_box_keypair();    // X25519 (Curve25519)

  edSecret = Buffer.from(edKeypair.privateKey);
  edPublic = Buffer.from(edKeypair.publicKey);
  xSecret  = Buffer.from(xKeypair.privateKey);
  xPublic  = Buffer.from(xKeypair.publicKey);
  fingerprint = makeFingerprint(edPublic);

  // Generate new UUID for agentId
  opts.agentId = crypto.randomUUID();

  const payload = {
    agent_id: opts.agentId,
    ed25519: { public: edPublic.toString('base64'), secret: edSecret.toString('base64') },
    x25519:  { public: xPublic.toString('base64'),  secret: xSecret.toString('base64')  },
    fingerprint,
    created_at: new Date().toISOString(),
  };
  fs.writeFileSync(KEYS_FILE, JSON.stringify(payload, null, 2), { mode: 0o600 });
}

/** SHA256 fingerprint of public key (hex) */
export function makeFingerprint(pubBuf) {
  return 'SHA256:' + crypto.createHash('sha256').update(pubBuf).digest('hex');
}

/** Loads client state from ~/.viberra/clients.json */
export function loadAgentState() {
  try {
    if (fs.existsSync(CLIENTS_FILE)) {
      const raw = fs.readFileSync(CLIENTS_FILE, 'utf8');
      const j = JSON.parse(raw);
      agentState.trusted_clients = j.trusted_clients || {};
      agentState.connections = Array.isArray(j.connections) ? j.connections : [];
    }
  } catch (e) {
    logW('Failed to load clients state: %s', e?.message || e);
    agentState.trusted_clients = {};
    agentState.connections = [];
  }
}

/** Saves client state to ~/.viberra/clients.json */
export function saveAgentState() {
  try {
    const payload = JSON.stringify(agentState, null, 2);
    fs.writeFileSync(CLIENTS_FILE, payload, { mode: 0o600 });
  } catch (e) {
    logW('Failed to save clients state: %s', e?.message || e);
  }
}

/** Adds or updates trusted client */
export function upsertTrustedClient({ device_id, fingerprint, label, psk_b64, client_sign_pub }) {
  if (!device_id) return;
  const now = new Date().toISOString();
  const existing = agentState.trusted_clients[device_id] || {};

  agentState.trusted_clients[device_id] = {
    device_id,
    fingerprint: fingerprint || existing.fingerprint || '',
    label: (label || existing.label || '').toString(),
    first_seen: existing.first_seen || now,
    last_seen: now,
    psk_b64: psk_b64 !== undefined ? psk_b64 : existing.psk_b64,  // Save PSK for E2EE
    client_sign_pub: client_sign_pub !== undefined ? client_sign_pub : existing.client_sign_pub,  // Ed25519 for enc_hello
  };

  saveAgentState();
}

/** Adds connection event to history */
export function addConnectionEvent({ device_id, label, fingerprint, room_id }) {
  if (!device_id) return;
  const ts = new Date().toISOString();

  agentState.connections.push({
    ts,
    device_id,
    label: label || '',
    fingerprint: fingerprint || '',
    room_id: room_id || '',
  });

  if (agentState.connections.length > MAX_CONNECTIONS) {
    agentState.connections = agentState.connections.slice(-MAX_CONNECTIONS);
  }

  saveAgentState();
}

/**
 * Gets PSK for specific client
 * @param {string} deviceId - Client device ID
 * @returns {Buffer|null} PSK or null if not found
 */
export function getPSKForClient(deviceId) {
  const client = agentState.trusted_clients[deviceId];
  if (!client || !client.psk_b64) return null;
  return Buffer.from(client.psk_b64, 'base64');
}

/**
 * Computes PSK from X25519 ECDH
 * @param {Buffer} clientStaticPub - Client X25519 public key (32 bytes)
 * @param {string} agentId - Agent ID
 * @param {string} clientDeviceId - Client device ID
 * @returns {Buffer} PSK (32 bytes)
 */
export function computePSK(clientStaticPub, agentId, clientDeviceId) {
  // ECDH: sharedRaw = X25519(agent.sk, client.pk)
  const sharedRaw = sodium.crypto_scalarmult(xSecret, clientStaticPub);

  // KDF: PSK = BLAKE2b-256(sharedRaw || context || agentId || clientDeviceId)
  const ctx = Buffer.from('viberra-psk-v1', 'utf8');
  const agentIdBuf = Buffer.from(agentId, 'utf8');
  const clientIdBuf = Buffer.from(clientDeviceId, 'utf8');

  const input = Buffer.concat([sharedRaw, ctx, agentIdBuf, clientIdBuf]);
  const psk = Buffer.from(sodium.crypto_generichash(32, input));

  return psk;
}
