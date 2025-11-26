import process from 'node:process';
import crypto from 'node:crypto';
import readline from 'node:readline';
import WebSocket from 'ws';
import SimplePeer from 'simple-peer';
import sodium from 'libsodium-wrappers-sumo';
import qrcode from 'qrcode-terminal';
import { opts, WRTC, HELLO_CTX, PAIR_CTX, RETRY_DELAY_MS, pairCode, buildPairUrl } from './constants.mjs';
import { runtime as state, agentState, resetEncState } from './state.mjs';
import { log, logW, logE } from './logger.mjs';
import { edSecret, edPublic, xPublic, upsertTrustedClient, addConnectionEvent, computePSK, getPSKForClient } from './crypto.mjs';
import { resetRingAndResize, markSizeOkAndFlush, flushSendPending } from './pty.mjs';
import { collectIceStats, attachIceDebug, normalizeIceServers, safeParseJSON } from './webrtc.mjs';
import { frameCtrl, framePty, parseFrame, toBuffer } from './framing-helpers.mjs';
import { deriveSessionKeys, encryptChunk, decryptChunk } from './webrtc-crypto.mjs';

/** Safely executes interactive function: disables raw mode and unsubscribes stdin,
 *  then restores everything back. */
async function withInteractiveInput(fn) {
  const hadTty = !!(opts.localTty && process.stdin?.isTTY);
  const wasRaw = hadTty && !!process.stdin.isRaw;

  if (hadTty) {
    try { if (wasRaw) process.stdin.setRawMode(false); } catch {}
    try { if (state.onStdinData) process.stdin.off('data', state.onStdinData); } catch {}
  }
  try {
    return await fn();
  } finally {
    if (hadTty) {
      try { if (state.onStdinData) process.stdin.on('data', state.onStdinData); } catch {}
      try { if (wasRaw) process.stdin.setRawMode(true); } catch {}
    }
  }
}

/** Simple y/n question with retries and timeout. Returns true/false or null on timeout. */
function askYesNo(promptText, { defaultNo = true, retries = 2, timeoutMs = 60_000 } = {}) {
  return withInteractiveInput(() =>
    new Promise((resolve) => {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

      let timer = setTimeout(() => {
        try { rl.close(); } catch {}
        resolve(null); // timeout → silently reject above
      }, timeoutMs);

      rl.on('SIGINT', () => { // Ctrl+C during question → reject
        clearTimeout(timer);
        try { rl.close(); } catch {}
        resolve(false);
      });

      const hint = defaultNo ? '[y/N]' : '[Y/n]';

      const ask = (attempt = 0) => {
        rl.question(`${promptText} ${hint} `, (line) => {
          const v = String(line || '').trim().toLowerCase();
          if (v === '') {
            clearTimeout(timer);
            try { rl.close(); } catch {}
            resolve(!defaultNo); // empty input → default answer
            return;
          }
          if (/^y(es)?$/.test(v)) {
            clearTimeout(timer);
            try { rl.close(); } catch {}
            resolve(true);
            return;
          }
          if (/^n(o)?$/.test(v)) {
            clearTimeout(timer);
            try { rl.close(); } catch {}
            resolve(false);
            return;
          }
          if (attempt < retries) {
            process.stdout.write('Enter y or n and press Enter.\n');
            ask(attempt + 1);
          } else {
            clearTimeout(timer);
            try { rl.close(); } catch {}
            resolve(false); // after exhausting retries — No
          }
        });
      };

      ask();
    })
  );
}

/** Handler for single pairing request. Ensures single-flight and KISS behavior. */
async function handlePairRequestKISS(msg) {
  if (state.pairPromptActive) {
    logW('Pair request ignored: prompt already active');
    // KISS: immediately reject parallel request so server doesn't wait
    try {
      sendControl({
        type: 'pair_decision',
        challenge_id: msg.challenge_id,
        accept: false,
        code: msg.code,
        agent_sign_pub: edPublic.toString('base64'),
        agent_static_pub: xPublic.toString('base64'),
        sig: '', // no signature on rejection
      });
    } catch {}
    return;
  }

  state.pairPromptActive = true;
  try {
    const { challenge_id, nonce, code, client } = msg;
    const okCode = String(code || '').trim() === String(pairCode);

    const banner = `
=== CLIENT PAIRING ===
Client: ${client?.label || client?.device_id}
Fingerprint: ${client?.fingerprint || '-'}
Code: ${code}   (expected: ${pairCode}) ${okCode ? '' : '[MISMATCH]'}
`;
    process.stdout.write(banner);

    // Ask user; Enter defaults to No, timeout = 60s
    const userSaysYes = await askYesNo('Pair this client?', { defaultNo: true, retries: 2, timeoutMs: 60_000 });

    // If timeout → treat as rejection
    let accept = !!userSaysYes && okCode;

    // CRITICAL: check required signature fields (MITM protection)
    if (accept && (!client?.sign_pub || !client?.static_sig || client?.static_ts === undefined)) {
      logE('[SECURITY] Missing client signature fields (sign_pub/static_sig/static_ts) - REJECTING pairing');
      process.stdout.write('⚠️  SECURITY: Client must provide signature - pairing rejected!\n');
      accept = false;
    }

    // Signature for challenge (old, for server compatibility)
    let sigB64 = '';
    if (accept) {
      const m = Buffer.concat([
        PAIR_CTX,
        Buffer.from(nonce, 'base64'),
        Buffer.from(String(client?.device_id || ''), 'utf8'),
        Buffer.from(String(code || ''), 'utf8'),
      ]);
      const sig = sodium.crypto_sign_detached(m, edSecret);
      sigB64 = Buffer.from(sig).toString('base64');
    }

    // Signature for agent_static_pub (protects against MITM X25519 key substitution)
    // Format: 'viberra-static-v1' || static_pub || timestamp || agentId
    const staticTs = Date.now();
    const staticCtx = Buffer.from('viberra-static-v1', 'utf8');
    const staticTsBuf = Buffer.from(String(staticTs), 'utf8');
    const agentIdBuf = Buffer.from(opts.agentId, 'utf8');
    const staticPayload = Buffer.concat([staticCtx, xPublic, staticTsBuf, agentIdBuf]);
    const staticSig = sodium.crypto_sign_detached(staticPayload, edSecret);
    const staticSigB64 = Buffer.from(staticSig).toString('base64');

    sendControl({
      type: 'pair_decision',
      challenge_id,
      accept,
      code,
      agent_sign_pub: edPublic.toString('base64'),
      agent_static_pub: xPublic.toString('base64'),
      agent_static_ts: staticTs,
      agent_static_sig: staticSigB64,
      sig: sigB64,
    });

    // If pairing successful — compute PSK and add client to trusted
    if (accept && client?.device_id) {
      let psk_b64 = null;

      // Compute PSK if client provided X25519 public key
      if (client.static_pub) {
        try {
          const clientStaticPub = Buffer.from(client.static_pub, 'base64');
          if (clientStaticPub.length !== 32) {
            logW('[SECURITY] Invalid client static_pub length: %d', clientStaticPub.length);
          } else {
            // Verify client_static_pub signature (protects against MITM X25519 key substitution)
            if (client.sign_pub && client.static_sig && client.static_ts) {
              const clientSignPub = Buffer.from(client.sign_pub, 'base64');
              const clientStaticSig = Buffer.from(client.static_sig, 'base64');

              // Assemble payload exactly like client does
              const staticCtx = Buffer.from('viberra-static-v1', 'utf8');
              const staticTsBuf = Buffer.from(String(client.static_ts), 'utf8');
              const clientIdBuf = Buffer.from(client.device_id, 'utf8');
              const staticPayload = Buffer.concat([staticCtx, clientStaticPub, staticTsBuf, clientIdBuf]);

              // Verify signature
              const sigValid = sodium.crypto_sign_verify_detached(clientStaticSig, staticPayload, clientSignPub);

              if (!sigValid) {
                logE('[SECURITY] Invalid client_static_pub signature - MITM detected! Rejecting pairing.');
                process.stdout.write('⚠️  SECURITY: Invalid client signature - possible MITM attack!\n');
                // DO NOT compute PSK with invalid signature
                psk_b64 = null;
              } else {
                log('[SECURITY] ✓ client_static_pub signature verified');

                // Check for key rotation (if device_id already exists in trusted_clients)
                const existing = agentState.trusted_clients[client.device_id];
                if (existing?.client_sign_pub) {
                  const existingPub = Buffer.from(existing.client_sign_pub, 'base64');
                  if (!existingPub.equals(clientSignPub)) {
                    logW('[SECURITY] Client sign_pub changed for device %s!', client.device_id);
                    process.stdout.write('⚠️  WARNING: Client Ed25519 key changed (key rotation detected)\n');
                  }
                }

                // Only after verification - compute PSK
                const psk = computePSK(clientStaticPub, opts.agentId, client.device_id);
                psk_b64 = psk.toString('base64');
                process.stdout.write('✓ PSK computed for E2EE\n');
              }
            }
            // IMPORTANT: if no signature - pairing already rejected above (line 138-142)
          }
        } catch (e) {
          logW('Failed to compute PSK: %s', e?.message || e);
        }
      }

      upsertTrustedClient({
        device_id: client.device_id,
        fingerprint: client.fingerprint || '',
        label: client.label || '',
        psk_b64,
        client_sign_pub: client.sign_pub || null,  // Ed25519 public key to verify enc_hello
      });
      process.stdout.write('Client added to trusted.\n');
    } else if (!accept) {
      process.stdout.write('Rejected.\n');
    }
  } catch (e) {
    logW('Pair prompt error: %s', e?.message || e);
    // On any failure — safe rejection
    try {
      sendControl({
        type: 'pair_decision',
        challenge_id: msg.challenge_id,
        accept: false,
        code: msg.code,
        agent_sign_pub: edPublic.toString('base64'),
        agent_static_pub: xPublic.toString('base64'),
        sig: '',
      });
    } catch {}
    process.stdout.write('Rejected (error).\n');
  } finally {
    state.pairPromptActive = false;
  }
}

/** Schedules automatic PASETO token renewal 60 seconds before expiration */
function scheduleRenew() {
  if (state.renewTimer) {
    clearTimeout(state.renewTimer);
    state.renewTimer = null;
  }

  if (!state.sessionToken || !state.sessionExp) return;

  const now = Math.floor(Date.now() / 1000);
  const timeUntilExpiry = state.sessionExp - now;

  // Renew 60 seconds before expiration
  const renewInSec = Math.max(1, timeUntilExpiry - 60);

  log('Scheduling token renewal in %d seconds', renewInSec);

  state.renewTimer = setTimeout(() => {
    if (state.control?.readyState === WebSocket.OPEN) {
      sendControl({ type: 'renew_token' });
    }
  }, renewInSec * 1000);
}

/** Establishes WSS connection, performs handshake and sends heartbeat. */
export function connectControl(spawnInitialPTY) {
  if (state.control?.readyState === WebSocket.OPEN) return;

  state.control = new WebSocket(opts.controlUrl);

  state.control.on('open',  () => log('Control connected: %s', opts.controlUrl));
  state.control.on('close', () => {
    logW('Control disconnected; retry in %d ms', RETRY_DELAY_MS);
    if (state.hbTimer) { clearInterval(state.hbTimer); state.hbTimer = null; }
    if (state.renewTimer) { clearTimeout(state.renewTimer); state.renewTimer = null; }
    setTimeout(() => connectControl(spawnInitialPTY), RETRY_DELAY_MS);
  });
  state.control.on('error', (e) => logE('Control error: %s', e?.message || e));

  state.control.on('message', (raw) => {
    const msg = safeParseJSON(raw);
    if (!msg?.type) return;

    switch (msg.type) {
      case 'server_hello': {
        // New Ed25519 authentication protocol
        const serverNonce = Buffer.from(msg.nonce, 'base64');
        const ts = Math.floor(Date.now() / 1000);

        // Token binding - use token hash if available, otherwise 32 zero bytes
        let tokenHashBuf;
        if (state.sessionToken) {
          // On reconnection with token - compute SHA256(token)
          tokenHashBuf = crypto.createHash('sha256').update(state.sessionToken).digest();
        } else {
          // On first connection or without token - 32 zero bytes
          tokenHashBuf = Buffer.alloc(32, 0);
        }

        // Form body for signature with token binding
        const body = Buffer.concat([
          HELLO_CTX,
          serverNonce,
          Buffer.from(opts.agentId, 'utf8'),
          Buffer.from(String(ts), 'utf8'),
          edPublic, // 32 bytes - Ed25519 public key
          tokenHashBuf, // 32 bytes - SHA256(token) or zeros for binding
        ]);

        // Sign using Ed25519
        const sig = sodium.crypto_sign_detached(body, edSecret); // Uint8Array(64)

        const helloMsg = {
          type: 'agent_hello',
          agent_device_id: opts.agentId,
          agent_device_label: opts.deviceLabel,
          agent_workdir: opts.launchCwd,
          version: opts.agentVersion,
          ts,
          agent_sign_pub: edPublic.toString('base64'), // Send public key (required for unpaired agents)
          sig: Buffer.from(sig).toString('base64'),
          token_hash: tokenHashBuf.toString('base64'), // Always send hash for binding
        };

        // If reconnection mode enabled - send flag to server
        if (opts.pairingMode) {
          helloMsg.pairing_mode = true;
        }

        // If active token exists - send it for reconnection
        if (state.sessionToken && state.sessionExp > ts) {
          helloMsg.token = state.sessionToken;
        }

        sendControl(helloMsg);
        break;
      }

      case 'hello_ok': {
        const intervalSec = Number(msg.interval || 15);
        if (state.hbTimer) clearInterval(state.hbTimer);
        state.hbTimer = setInterval(
            () => sendControl({ type: 'heartbeat', ts: Math.floor(Date.now()/1000), version: opts.agentVersion }),
            intervalSec * 1000,
        );
        const mode = msg.mode || 'READY';

        // Save new PASETO token if received
        if (msg.session_token && msg.exp) {
          state.sessionToken = msg.session_token;
          state.sessionExp = msg.exp;
          scheduleRenew(); // Schedule automatic renewal
          log('Auth OK; mode=%s; heartbeat every %d s; token expires at %d', mode, intervalSec, state.sessionExp);
        } else {
          log('Auth OK; mode=%s; heartbeat every %d s; no token', mode, intervalSec);
        }

        // Show summary of trusted clients and recent connections
        const clients = Object.values(agentState.trusted_clients);
        if (clients.length > 0) {
          process.stdout.write('\n\x1b[1m=== Trusted Clients ===\x1b[0m\n');
          process.stdout.write('\x1b[37m');
          for (const c of clients) {
            const label = c.label || c.device_id;
            process.stdout.write(`- ${label}  (${c.device_id})\n  ${c.fingerprint}\n  first: ${c.first_seen}, last: ${c.last_seen}\n\n`);
          }
          process.stdout.write('\x1b[0m');
        } else {
          process.stdout.write('\nNo trusted clients yet. Scan QR to pair.\n\n');
        }

        const last = agentState.connections.slice(-5);
        if (last.length > 0) {
          process.stdout.write('\x1b[1m=== Recent Connections ===\x1b[0m\n');
          process.stdout.write('\x1b[37m');
          for (const ev of last) {
            const label = ev.label || ev.device_id;
            process.stdout.write(`- ${ev.ts}: ${label} (device_id=${ev.device_id}) room=${ev.room_id}\n`);
          }
          process.stdout.write('\x1b[0m\n');
        }

        // PTY startup logic depending on mode
        if (mode === 'READY' && !opts.pairingMode) {
          // Agent already paired and NOT in reconnection mode → start PTY immediately
          if (!state.term) spawnInitialPTY();
        } else {
          // PAIRING_ONLY or reconnection mode (--pair-mode) — show QR with link
          const url = buildPairUrl();
          log('PAIR-QR link: %s', url);

          process.stdout.write('\n=== Agent Pairing ===\n');
          process.stdout.write('Scan QR code to pair agent:\n\n');

          try { qrcode.generate(url, { small: true }); } catch {}

          process.stdout.write(`\nOr go to the link: ${url}\n\n`);

          // and wait for pair_request from server
        }
        break;
      }

      case 'token_update': {
        // Server sent updated PASETO token
        if (msg.session_token && msg.exp) {
          state.sessionToken = msg.session_token;
          state.sessionExp = msg.exp;
          scheduleRenew(); // Reschedule next renewal
          log('Token renewed; expires at %d', state.sessionExp);
        }
        break;
      }

      case 'invite': {
        //if (state.current) {
        //  logW('Invite ignored: session already active'); break;
        //}
        const { room_id: roomId, iceServers, client } = msg;

        // ==================== E2EE: PSK Verification ====================
        const psk = getPSKForClient(client?.device_id);
        if (!psk) {
          logE('No PSK for client %s - re-pairing required', client?.device_id);
          sendControl({
            type: 'error',
            room_id: roomId,
            message: 'Re-pairing required: no PSK for E2EE'
          });
          break;
        }

        // Derive session keys from PSK + room_id
        const { keyA2C, keyC2A, noncePrefixA2C, noncePrefixC2A } = deriveSessionKeys(
          sodium,
          psk,
          roomId
        );

        // Reset and initialize encState for new session
        resetEncState();
        state.enc.keySend = keyA2C;
        state.enc.keyRecv = keyC2A;
        state.enc.noncePrefixSend = noncePrefixA2C;
        state.enc.noncePrefixRecv = noncePrefixC2A;
        state.enc.sendCounter = 0n;
        state.enc.recvCounter = 0n;
        state.enc.ready = false;  // Will become true after enc_hello handshake
        state.enc.handshakeInProgress = true;

        log('E2EE session keys derived for room %s', roomId);
        // ============================================================

        const sp = new SimplePeer({
          initiator: false,
          trickle: true,
          wrtc: WRTC,
          config: {
            iceServers: normalizeIceServers(iceServers) //, iceTransportPolicy: 'relay'
          },
        });

        // Detailed ICE state logging
        attachIceDebug(sp, {
          roomId,
          clientDeviceId: client?.device_id,
          agentDeviceId: opts.agentId,
        });

        // our signals → controller (it will forward to client)
        sp.on('signal', (data) => {
          try {
            if (data.type === 'offer' || data.type === 'answer') {
              log(
                'SP signal (%s) room=%s sdp_len=%d',
                data.type,
                roomId,
                data.sdp ? data.sdp.length : 0
              );
            } else if (data.candidate) {
              log(
                'SP signal (candidate) room=%s candidate=%s',
                roomId,
                data.candidate?.candidate || ''
              );
            } else {
              log('SP signal (other) room=%s: %j', roomId, data);
            }
          } catch {}

          sendControl({ type: 'rtc_signal_from_agent', room_id: roomId, data });
        });

        // connection established — send enc_hello handshake
        sp.on('connect', () => {
          log('SP connected (room: %s)', roomId);

          // ==================== E2EE: Send enc_hello ====================
          // Form psk_fp for client-side verification
          const pskFp = crypto.createHash('sha256').update(psk).digest();
          const pskFpB64 = pskFp.toString('base64');
          const ts = Date.now();

          // Byte payload for signature (NOT JSON string!)
          const payload = Buffer.concat([
            Buffer.from('viberra-enc-hello-v1', 'utf8'),
            Buffer.from(roomId, 'utf8'),
            Buffer.from(opts.agentId, 'utf8'),
            Buffer.from(String(ts), 'utf8'),
            pskFp,
          ]);

          const sig = sodium.crypto_sign_detached(payload, edSecret);

          // Send plaintext enc_hello
          try {
            sp.send(frameCtrl({
              type: 'enc_hello',
              room_id: roomId,
              sender_id: opts.agentId,
              ts,
              psk_fp: pskFpB64,
              sig: Buffer.from(sig).toString('base64'),
            }));
          } catch (e) {
            logE('Failed to send enc_hello: %s', e?.message || e);
          }

          // Set handshake timeout
          const handshakeTimeout = setTimeout(() => {
            if (!state.enc.ready) {
              logE('E2EE handshake timeout for room %s', roomId);
              try { sp.destroy(); } catch {}
            }
          }, 5000);

          // Save timeout for later cleanup
          state.enc.handshakeTimeout = handshakeTimeout;
          // ==================================================================

          // Log client connection
          if (client && client.device_id) {
            const clientLabel = client.label || client.device_id;
            log('Connected: %s (%s)', clientLabel, client.device_id);

            // Record connection event in history
            addConnectionEvent({
              device_id: client.device_id,
              label: client.label || '',
              fingerprint: client.fingerprint || '',
              room_id: roomId,
            });

            // Update last_seen for trusted client
            upsertTrustedClient({
              device_id: client.device_id,
              label: client.label || '',
              fingerprint: client.fingerprint || '',
            });
          }

          // CRITICAL: DO NOT send resize until handshake complete!
          // This will be done later after enc.ready = true
        });

        // data from client → E2EE → PTY
        sp.on('data', (data) => {
          // ==================== E2EE: Handshake Verification ====================
          if (!state.enc.ready) {
            // ONLY enc_hello in plaintext is allowed
            const buf = toBuffer(data);
            const f = parseFrame(buf);

            if (f.type !== 'ctrl' || f.json?.type !== 'enc_hello') {
              logE('E2EE handshake not complete, but received non-enc_hello frame');
              try { sp.destroy(); } catch {}
              return;
            }

            const { room_id, sender_id, ts, psk_fp, sig } = f.json;

            // Verify client signature (get public key from trusted)
            const clientData = agentState.trusted_clients[sender_id];
            if (!clientData) {
              logE('Unknown client %s in enc_hello', sender_id);
              try { sp.destroy(); } catch {}
              return;
            }

            // Verify enc_hello signature (protects against MITM and confirms identity)
            if (!clientData.client_sign_pub) {
              logE('[SECURITY] No client_sign_pub stored for device %s - cannot verify enc_hello signature', sender_id);
              try { sp.destroy(); } catch {}
              return;
            }

            const clientSignPub = Buffer.from(clientData.client_sign_pub, 'base64');
            const sigBuf = Buffer.from(sig, 'base64');

            // Payload: 'viberra-enc-hello-v1' || room_id || sender_id || ts || psk_fp
            const payload = Buffer.concat([
              Buffer.from('viberra-enc-hello-v1', 'utf8'),
              Buffer.from(room_id, 'utf8'),
              Buffer.from(sender_id, 'utf8'),
              Buffer.from(String(ts), 'utf8'),
              Buffer.from(psk_fp, 'base64'),
            ]);

            const sigValid = sodium.crypto_sign_verify_detached(sigBuf, payload, clientSignPub);
            if (!sigValid) {
              logE('[SECURITY] enc_hello signature invalid from client %s', sender_id);
              try { sp.destroy(); } catch {}
              return;
            }

            log('[SECURITY] ✓ enc_hello signature verified for client %s', sender_id);

            // Verify psk_fp
            const localPskFp = crypto.createHash('sha256').update(psk).digest('base64');
            if (psk_fp !== localPskFp) {
              logE('PSK fingerprint mismatch - re-pairing required');
              try { sp.destroy(); } catch {}
              return;
            }

            // ✅ Handshake successful
            if (state.enc.handshakeTimeout) {
              clearTimeout(state.enc.handshakeTimeout);
              state.enc.handshakeTimeout = null;
            }
            state.enc.ready = true;
            state.enc.handshakeInProgress = false;
            log('✓ E2EE established for room %s', roomId);

            // Now we can send resize to client (encrypted!)
            try {
              const resizeFrame = frameCtrl({
                type: 'resize',
                cols: state.term?.cols ?? 100,
                rows: state.term?.rows ?? 30
              });
              const encrypted = encryptChunk(sodium, state.enc, resizeFrame);
              sp.send(encrypted);
            } catch (e) {
              logW('Failed to send encrypted resize: %s', e?.message || e);
            }

            return;
          }
          // ==================================================================

          if (!state.term) return;

          // ==================== E2EE: Decryption ====================
          let plain;
          try {
            plain = decryptChunk(sodium, state.enc, toBuffer(data));
          } catch (e) {
            logE('E2EE decryption failed: %s', e?.message || e);
            try { sp.destroy(); } catch {}
            return;
          }

          const f = parseFrame(plain);
          // ===========================================================

          if (f.type === 'ctrl') {
            const j = f.json;

            // Heartbeat ping/pong (now encrypted!)
            if (j?.type === 'ping') {
              try {
                const pongFrame = frameCtrl({
                  type: 'pong',
                  ts: j.ts || Date.now(),
                });
                const encrypted = encryptChunk(sodium, state.enc, pongFrame);
                sp.send(encrypted);
              } catch (e) {
                logW('Failed to send pong: %s', e?.message || e);
              }
              return;
            }

            if (j?.type === 'resize' && Number.isInteger(j.cols) && Number.isInteger(j.rows)) {
              // Client requested resize: take minimum of (client, local TTY if present)
              const clientCols = Math.max(1, j.cols | 0);
              const clientRows = Math.max(1, j.rows | 0);
              state.lastClientSize = { cols: clientCols, rows: clientRows };

              const haveLocalTty = !!(opts.localTty && process.stdout?.isTTY);
              const localCols = haveLocalTty && Number.isInteger(process.stdout?.columns)
                ? process.stdout.columns : Infinity;
              const localRows = haveLocalTty && Number.isInteger(process.stdout?.rows)
                ? process.stdout.rows : Infinity;

              const cols = Number.isFinite(localCols) ? Math.min(clientCols, localCols) : clientCols;
              const rows = Number.isFinite(localRows) ? Math.min(clientRows, localRows) : clientRows;

              // First resize from client → hard clear buffer and resize,
              // to "reset" render history before stream begins
              const isFirstClientResize = state.current && state.current.peer === sp && !state.current.sizeOk;

              resetRingAndResize(cols, rows, { force: true });

              // Complete handshake: enable PTY → client flow
              if (state.current && state.current.peer === sp && !state.current.sizeOk) {
                markSizeOkAndFlush();
              }
            }
            return;
          }

          if (f.type === 'pty') {
            try { state.term.write(f.buf); } catch {}
            return;
          }

          // unknown / bad-ctrl — can log
          if (f.type === 'bad-ctrl' || f.type === 'unknown') {
            logW('Unknown frame type: %s', f.type);
          }
        });

        const end = () => {
          log('SP disconnected (room: %s)', state.current?.roomId ?? 'N/A');

          // Clean up E2EE state
          if (state.enc.handshakeTimeout) {
            clearTimeout(state.enc.handshakeTimeout);
          }
          resetEncState();

          if (state.current?.peer === sp) {
            flushSendPending('DISCONNECT');
            try { sp.destroy(); } catch {}

            state.current = null;

            // After session end restore PTY to local size,
            // and clear ring buffer via onResize()
            if (opts.localTty && process.stdout?.isTTY && typeof state.onResize === 'function') {
              try {
                state.onResize();
              } catch (e) {
                logW('Failed to restore local PTY size after session end: %s', e?.message || e);
              }
            } else {
              // Without local TTY — optionally just clear buffer,
              // but don't touch size to avoid breaking headless scenarios
              state.pendingChunk = Buffer.alloc(0);
              state.ringChunks = [];
              state.ringTotalBytes = 0;
            }
          }
        };
        sp.on('close', end);
        sp.on('error', (e) => {
          // Collect detailed diagnostics for ICE connection errors
          const iceStats = collectIceStats(sp);
          const errorContext = {
            roomId: roomId ?? 'unknown',
            agentId: opts.agentId ?? 'unknown',
            deviceLabel: opts.deviceLabel ?? 'unknown',
            ...iceStats,
          };

          // Log with full context via winston metadata
          logE('SP error: %s', e?.message || e, errorContext);
          end();
        });

        state.current = { peer: sp, kill: end, roomId, sizeOk: false };
        break;
      }

      case 'rtc_signal': {
        // signals from client → into peer.signal()
        const { room_id: roomId, data } = msg;
        if (state.current && state.current.roomId === roomId && data) {
          try {
            log(
              'SP incoming signal room=%s kind=%s',
              roomId,
              data.type || (data.candidate ? 'candidate' : 'unknown')
            );
            state.current.peer.signal(data);
          } catch (e) {
            logE('signal error: %s', e?.message || e);
          }
        }
        break;
      }

      case 'room.disconnected': {
        // Server closed room due to another client connecting or other reasons
        const roomId = msg.data?.room_id;
        if (state.current && state.current.roomId === roomId) {
          log('Room disconnected (reason: %s)', msg.data?.reason || 'unknown');
          if (state.current.kill) state.current.kill();
        }
        break;
      }

      case 'pair_request': {
        // New protocol: server sends {challenge_id, nonce, code, client: {device_id, fingerprint, label}}
        handlePairRequestKISS(msg);
        break;
      }

      case 'pair_ok': {
        // Successful pairing → start PTY
        if (!state.term) spawnInitialPTY();
        break;
      }
    }
  });
}

/** Safely sends JSON to Control-API. */
export function sendControl(obj) {
  try { if (state.control?.readyState === WebSocket.OPEN) state.control.send(JSON.stringify(obj)); } catch {}
}
