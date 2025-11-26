import sodiumModule from 'libsodium-wrappers-sumo';
import { getClockSkew, isSessionExpired } from './client-auth';

/**
 * WebSocket RPC Client for Viberra
 *
 * Handles:
 * - WebSocket connection with handshake
 * - RPC request/response with Ed25519 signatures
 * - Event subscriptions (push notifications from server)
 * - Automatic reconnection with exponential backoff
 */

const CLIENT_WS_HELLO_CTX = 'viberra-client-ws-hello-v1';
const CLIENT_CTX_RPC = 'viberra-client-rpc-v1';

class WSRPCClient {
  constructor(apiBase, deviceKey, sessionToken) {
    this.apiBase = apiBase;
    this.deviceKey = deviceKey; // { sk, pk } from client-auth.js
    this.sessionToken = sessionToken;
    this.ws = null;
    this.isConnected = false;
    this.pendingRequests = new Map(); // id -> { resolve, reject }
    this.eventListeners = new Map(); // eventType -> Set of callbacks
    this.reconnectAttempt = 0;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.heartbeatInterval = 15000; // Default 15 seconds
    this.connectPromise = null; // Lock for idempotent connect()
    this.socketGen = 0; // Socket generation counter to track races

    console.log('[WS-RPC] Client initialized', { apiBase });
  }

  /**
   * Deep key sorting (deterministic canonicalization)
   * Used for consistent params_hash computation in RPC signatures
   */
  static deepSort(value) {
    if (Array.isArray(value)) return value.map(WSRPCClient.deepSort);
    if (value && typeof value === 'object') {
      const out = {};
      for (const k of Object.keys(value).sort()) {
        out[k] = WSRPCClient.deepSort(value[k]);
      }
      return out;
    }
    return value;
  }

  /**
   * Establishes WebSocket connection and performs handshake (idempotent)
   */
  async connect() {
    // Already connected - nothing to do
    if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      console.log('[WS-RPC] Already connected');
      return;
    }

    // Connection already in progress - wait for it
    if (this.connectPromise) {
      console.log('[WS-RPC] Connection already in progress, waiting...');
      return this.connectPromise;
    }

    const wsUrl = this.apiBase.replace(/^http/, 'ws') + '/ws/client';
    console.log('[WS-RPC] Connecting to', wsUrl);

    // Increment socket generation to invalidate any pending operations from old sockets
    const gen = ++this.socketGen;
    const ws = new WebSocket(wsUrl);

    this.connectPromise = new Promise((resolve, reject) => {
      const cleanup = () => {
        if (this.connectPromise && gen === this.socketGen) {
          this.connectPromise = null;
        }
      };

      // Re-armable timeout for two-phase handshake
      let timeout;
      const arm = (ms, label) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
          cleanup();
          reject(new Error(`Handshake timeout: ${label}`));
          try { ws.close(); } catch {}
        }, ms);
      };
      arm(10000, 'server_hello');

      ws.onopen = () => {
        console.log('[WS-RPC] WebSocket opened, waiting for server_hello');
      };

      ws.onmessage = async (event) => {
        // Ignore messages from outdated socket generations
        if (gen !== this.socketGen) {
          console.log('[WS-RPC] Ignoring message from outdated socket generation');
          return;
        }

        try {
          const msg = JSON.parse(event.data);

          // Handle handshake
          if (msg.type === 'server_hello') {
            console.log('[WS-RPC] Received server_hello');
            arm(7000, 'hello_ok'); // Re-arm for second phase
            try {
              await this.sendClientHello(ws, msg); // Pass specific socket
            } catch (err) {
              console.error('[WS-RPC] Failed to send client_hello:', err);
              clearTimeout(timeout);
              cleanup();
              reject(err);
              try { ws.close(); } catch {}
            }
          }
          else if (msg.type === 'hello_ok') {
            clearTimeout(timeout); // Only here we finally clear the timeout
            console.log('[WS-RPC] Received hello_ok, connection established');

            // Only now set this.ws to the successfully connected socket
            this.ws = ws;
            this.isConnected = true;
            this.reconnectAttempt = 0;
            this.heartbeatInterval = (msg.interval || 15) * 1000;
            this.startHeartbeat();

            // Switch to normal message handler
            this.ws.onmessage = (e) => this.handleMessage(e);

            cleanup();
            resolve();
            console.log('[WS-RPC] Handshake complete');

            // Notify subscribers (DeviceAgentPanel awaits this event)
            this.dispatchEvent('open', { ts: Date.now() });
          }
          else {
            clearTimeout(timeout);
            cleanup();
            reject(new Error(`Unexpected message during handshake: ${msg.type}`));
            try { ws.close(); } catch {}
          }
        } catch (err) {
          clearTimeout(timeout);
          cleanup();
          reject(err);
        }
      };
      ws.onerror = (err) => {
        console.error('[WS-RPC] WebSocket error:', err);
        clearTimeout(timeout);
        cleanup();
        reject(err);
      };

      ws.onclose = (event) => {
        const code = event.code || '';
        const reason = event.reason || '';

        // 4401 — expected error on first connection (token still replicating)
        if (code === 4401) {
          console.log('[WS-RPC] WebSocket closed during handshake: 4401 (token not ready yet)');
        } else {
          console.log('[WS-RPC] WebSocket closed during handshake:', code, reason);
        }

        clearTimeout(timeout);
        // IMPORTANT: reject this attempt's promise so outer await doesn't hang
        const err = new Error(`WebSocket closed during handshake: ${code} ${reason}`.trim());
        if (code === 4401) err.soft = true; // Mark as soft error
        try { reject(err); } catch {}
        cleanup();
        // Let reconnect continue in background
        this.handleDisconnect();
      };
    });
    console.log('[WS-RPC] Connecting promise settled');
    return this.connectPromise;
  }

  /**
   * Sends client_hello with Ed25519 signature and token binding
   * @param {WebSocket} ws - Specific WebSocket instance to send to (avoid race with this.ws)
   * @param {object} serverHello - Server hello message
   */
  async sendClientHello(ws, serverHello) {
    await sodiumModule.ready;
    const S = sodiumModule;
    const enc = new TextEncoder();

    const serverNonce = this.base64ToUint8Array(serverHello.nonce);
    const ts = Math.floor(Date.now() / 1000) + (typeof getClockSkew === 'function' ? getClockSkew() : 0);

    // Compute device_id from public key hash (same as in client-auth.js)
    const deviceIdBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', this.deviceKey.pk));
    const deviceId = Array.from(deviceIdBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Token binding: SHA256(token)
    const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(this.sessionToken)));

    // Build message to sign: CTX || nonce || device_id || ts || public_key || token_hash
    const body = new Uint8Array(
      enc.encode(CLIENT_WS_HELLO_CTX).length +
      serverNonce.length +
      deviceId.length +
      String(ts).length +
      this.deviceKey.pk.length +
      tokenHash.length
    );

    let offset = 0;
    body.set(enc.encode(CLIENT_WS_HELLO_CTX), offset); offset += enc.encode(CLIENT_WS_HELLO_CTX).length;
    body.set(serverNonce, offset); offset += serverNonce.length;
    body.set(enc.encode(deviceId), offset); offset += deviceId.length;
    body.set(enc.encode(String(ts)), offset); offset += String(ts).length;
    body.set(this.deviceKey.pk, offset); offset += this.deviceKey.pk.length;
    body.set(tokenHash, offset);

    // Sign with Ed25519
    const sig = S.crypto_sign_detached(body, this.deviceKey.sk);

    const helloMsg = {
      type: 'client_hello',
      device_id: deviceId,
      ts,
      version: '1.0.0',
      token: this.sessionToken,
      token_hash: this.uint8ArrayToBase64(tokenHash),
      sig: this.uint8ArrayToBase64(sig)
    };

    // Use the specific socket instance, not this.ws which might have changed
    if (ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Socket not OPEN for client_hello (state: ${ws.readyState})`);
    }

    console.log('[WS-RPC] Sending client_hello');
    ws.send(JSON.stringify(helloMsg));
  }

  /**
   * Main message handler after handshake
   */
  handleMessage(event) {
    try {
      const msg = JSON.parse(event.data);

      // Handle RPC responses
      if (msg.id) {
        const pending = this.pendingRequests.get(msg.id);
        if (pending) {
          this.pendingRequests.delete(msg.id);
          if (msg.error) {
            pending.reject(new Error(`RPC Error ${msg.error.code}: ${msg.error.message}`));
          } else {
            pending.resolve(msg.result);
          }
        }
      }
      // Handle push events: dispatch by method name if available, otherwise by type
      else if (msg.type === 'push' && msg.method) {
        // Push event with method (e.g., room.disconnected, agents.update)
        this.dispatchEvent(msg.method, msg.data || msg);
      }
      else if (msg.type) {
        // Other push events
        this.dispatchEvent(msg.type, msg.data || msg);
      }
    } catch (err) {
      console.error('[WS-RPC] Failed to handle message:', err);
    }
  }

  /**
   * Calls an RPC method with parameters
   * @param {string} method - Method name (e.g., "agents.list")
   * @param {object} params - Method parameters
   * @returns {Promise<object>} - Method result
   */
  async call(method, params = {}) {
    if (!this.isConnected) {
      throw new Error('WebSocket not connected');
    }

    await sodiumModule.ready;
    const S = sodiumModule;
    const enc = new TextEncoder();

    const id = crypto.randomUUID();
    const ts = Math.floor(Date.now() / 1000) + (typeof getClockSkew === 'function' ? getClockSkew() : 0);
    const nonce = this.generateNonce();

    // Token binding: SHA256(token)
    const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(this.sessionToken)));

    // Canonicalize params using deep key sorting (for nested objects like SDP/ICE)
    const canonicalParams = WSRPCClient.deepSort(params);
    const paramsCanonical = JSON.stringify(canonicalParams);
    const paramsHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(paramsCanonical)));

    // Build signature body: CTX_RPC || method || ts || nonce || token_hash || params_hash
    const body = new Uint8Array(
      enc.encode(CLIENT_CTX_RPC).length +
      enc.encode(method).length +
      String(ts).length +
      nonce.length +
      tokenHash.length +
      paramsHash.length
    );

    let offset = 0;
    body.set(enc.encode(CLIENT_CTX_RPC), offset); offset += enc.encode(CLIENT_CTX_RPC).length;
    body.set(enc.encode(method), offset); offset += enc.encode(method).length;
    body.set(enc.encode(String(ts)), offset); offset += String(ts).length;
    body.set(enc.encode(nonce), offset); offset += nonce.length;
    body.set(tokenHash, offset); offset += tokenHash.length;
    body.set(paramsHash, offset);

    // Sign with Ed25519
    const sig = S.crypto_sign_detached(body, this.deviceKey.sk);

    // Send same canonicalized params (so byte representation matches signature)
    const request = {
      id,
      method,
      params: canonicalParams,
      ts,
      nonce,
      sig: this.uint8ArrayToBase64(sig)
    };

    console.log('[WS-RPC] →', method, canonicalParams);

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`RPC timeout: ${method}`));
        }
      }, 30000);

      this.ws.send(JSON.stringify(request));
    });
  }

  /**
   * Subscribe to server push events
   * @param {string} eventType - Event type (e.g., "rtc.signal")
   * @param {function} callback - Callback function
   */
  on(eventType, callback) {
    if (!this.eventListeners.has(eventType)) {
      this.eventListeners.set(eventType, new Set());
    }
    this.eventListeners.get(eventType).add(callback);
  }

  /**
   * Unsubscribe from events
   */
  off(eventType, callback) {
    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      listeners.delete(callback);
    }
  }

  /**
   * Dispatch event to all listeners
   */
  dispatchEvent(eventType, data) {
    console.log('[WS-RPC] Event:', eventType, data);
    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      listeners.forEach(callback => {
        try {
          callback(data);
        } catch (err) {
          console.error('[WS-RPC] Event handler error:', err);
        }
      });
    }
  }

  /**
   * Start heartbeat timer
   */
  startHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify({ type: 'heartbeat' }));
        } catch (err) {
          console.error('[WS-RPC] Heartbeat failed:', err);
        }
      }
    }, this.heartbeatInterval);
  }

  /**
   * Handle disconnection and attempt reconnect
   */
  handleDisconnect() {
    this.isConnected = false;

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    // Reject all pending requests
    this.pendingRequests.forEach(({ reject }) => {
      reject(new Error('WebSocket disconnected'));
    });
    this.pendingRequests.clear();

    // Don't reconnect if session has expired
    if (isSessionExpired()) {
      console.log('[WS-RPC] Session expired, skipping reconnect');
      return;
    }

    // Schedule reconnection with exponential backoff
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempt), 30000);
    console.log(`[WS-RPC] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempt + 1})`);

    this.reconnectTimer = setTimeout(() => {
      // Don't attempt reconnect if connection already in progress
      if (this.connectPromise) {
        console.log('[WS-RPC] Reconnect skipped - connection already in progress');
        return;
      }

      this.reconnectAttempt++;
      this.connect().catch(err => {
        console.error('[WS-RPC] Reconnection failed:', err);
      });
    }, delay);
  }

  /**
   * Close WebSocket connection
   */
  close() {
    console.log('[WS-RPC] Closing connection');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.ws) {
      try {
        this.ws.send(JSON.stringify({ type: 'bye' }));
        this.ws.close();
      } catch {}
      this.ws = null;
    }

    this.isConnected = false;
  }

  // Utility functions
  generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return this.uint8ArrayToBase64(bytes);
  }

  uint8ArrayToBase64(arr) {
    return sodiumModule.to_base64(arr, sodiumModule.base64_variants.ORIGINAL);
  }

  base64ToUint8Array(str) {
    const v = sodiumModule.base64_variants;
    for (const variant of [v.URLSAFE_NO_PADDING, v.URLSAFE, v.ORIGINAL_NO_PADDING, v.ORIGINAL]) {
      try { return sodiumModule.from_base64(str, variant); } catch {}
    }
    // Last-resort normalization
    let norm = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (norm.length % 4)) % 4;
    norm += '='.repeat(pad);
    return sodiumModule.from_base64(norm, v.ORIGINAL);
  }
}

let wsClient = null;
let initPromise = null; // Promise lock for idempotent initialization

/**
 * Initialize WebSocket RPC client (idempotent)
 * @param {string} apiBase - API base URL
 * @param {object} deviceKey - Device key pair { sk, pk }
 * @param {string} sessionToken - PASETO session token
 * @returns {Promise<WSRPCClient>}
 */
export async function initWSClient(apiBase, deviceKey, sessionToken) {
  // Client already exists and connected
  if (wsClient) {
    console.log('[WS-RPC] Client already initialized, reusing');
    if (!wsClient.isConnected) {
      await wsClient.connect();
    }
    return wsClient;
  }

  // Initialization already in progress - wait for it
  if (initPromise) {
    console.log('[WS-RPC] Initialization already in progress, waiting...');
    return initPromise;
  }

  console.log('[WS-RPC] Creating new client instance');
  wsClient = new WSRPCClient(apiBase, deviceKey, sessionToken);

  initPromise = wsClient.connect()
    .then(() => wsClient)
    .finally(() => {
      initPromise = null;
    });

  return initPromise;
}

/**
 * Get the current WebSocket RPC client instance
 * @returns {WSRPCClient|null}
 */
export function getWSClient() {
  return wsClient;
}

/**
 * Close and cleanup WebSocket client
 */
export function closeWSClient() {
  if (wsClient) {
    wsClient.close();
    wsClient = null;
  }
}
