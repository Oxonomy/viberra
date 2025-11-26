const DB_NAME = 'viberra';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const DEVICE_KEY_ID = 'dev_device_sk';
const CLIENT_STATIC_KEY_ID = 'dev_client_static_sk'; // X25519 for ECDH with agent
const PSK_PREFIX = 'psk_'; // PSK for agents: 'psk_<agent_id>'
const AGENT_SIGN_PUB_PREFIX = 'agent_sign_pub_'; // Ed25519 public keys of agents for enc_hello verification

/**
 * Opens IndexedDB. Returns null on error.
 * @returns {Promise<IDBDatabase|null>}
 */
function openKeyDB() {
  return new Promise((resolve) => {
    try {
      if (!window.indexedDB) {
        console.warn('[key-store] IndexedDB not available');
        resolve(null);
        return;
      }

      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = () => {
        try {
          const db = request.result;
          if (!db.objectStoreNames.contains(STORE_NAME)) {
            db.createObjectStore(STORE_NAME);
          }
        } catch (e) {
          console.warn('[key-store] Failed to create object store:', e?.message || e);
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => {
        console.warn('[key-store] Failed to open IndexedDB:', request.error?.message || request.error);
        resolve(null);
      };
    } catch (e) {
      console.warn('[key-store] IndexedDB exception:', e?.message || e);
      resolve(null);
    }
  });
}

/**
 * Loads device secret key (base64) from IndexedDB.
 * @returns {Promise<string|null>} base64 string or null
 */
export async function loadDeviceSecretB64() {
  try {
    const db = await openKeyDB();
    if (!db) return null;

    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(DEVICE_KEY_ID);

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => {
          console.warn('[key-store] Failed to read key:', req.error?.message || req.error);
          resolve(null);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(null);
      }
    });
  } catch (e) {
    console.warn('[key-store] loadDeviceSecretB64 failed:', e?.message || e);
    return null;
  }
}

/**
 * Saves device secret key (base64) to IndexedDB.
 * @param {string} b64 - base64 key string
 * @returns {Promise<boolean>} true if successful, false on error
 */
export async function saveDeviceSecretB64(b64) {
  try {
    const db = await openKeyDB();
    if (!db) return false;

    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(b64, DEVICE_KEY_ID);

        req.onsuccess = () => resolve(true);
        req.onerror = () => {
          console.warn('[key-store] Failed to write key:', req.error?.message || req.error);
          resolve(false);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(false);
      }
    });
  } catch (e) {
    console.warn('[key-store] saveDeviceSecretB64 failed:', e?.message || e);
    return false;
  }
}

/**
 * Load client static key (X25519, base64) from IndexedDB.
 * @returns {Promise<string|null>} base64 string or null
 */
export async function loadClientStaticKeyB64() {
  try {
    const db = await openKeyDB();
    if (!db) return null;

    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(CLIENT_STATIC_KEY_ID);

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => {
          console.warn('[key-store] Failed to read client static key:', req.error?.message || req.error);
          resolve(null);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(null);
      }
    });
  } catch (e) {
    console.warn('[key-store] loadClientStaticKeyB64 failed:', e?.message || e);
    return null;
  }
}

/**
 * Save client static key (X25519, base64) to IndexedDB.
 * @param {string} b64 - base64 string of X25519 private key (32 bytes)
 * @returns {Promise<boolean>} true if successful
 */
export async function saveClientStaticKeyB64(b64) {
  try {
    const db = await openKeyDB();
    if (!db) return false;

    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(b64, CLIENT_STATIC_KEY_ID);

        req.onsuccess = () => resolve(true);
        req.onerror = () => {
          console.warn('[key-store] Failed to write client static key:', req.error?.message || req.error);
          resolve(false);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(false);
      }
    });
  } catch (e) {
    console.warn('[key-store] saveClientStaticKeyB64 failed:', e?.message || e);
    return false;
  }
}

/**
 * Load PSK for specific agent from IndexedDB.
 * @param {string} agentId - Agent ID
 * @returns {Promise<string|null>} base64 string of PSK (32 bytes) or null
 */
export async function loadPSK(agentId) {
  try {
    const db = await openKeyDB();
    if (!db) return null;

    const key = PSK_PREFIX + agentId;
    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(key);

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => {
          console.warn('[key-store] Failed to read PSK for agent:', agentId, req.error?.message || req.error);
          resolve(null);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(null);
      }
    });
  } catch (e) {
    console.warn('[key-store] loadPSK failed:', e?.message || e);
    return null;
  }
}

/**
 * Save PSK for specific agent to IndexedDB.
 * @param {string} agentId - Agent ID
 * @param {string} pskBase64 - base64 string of PSK (32 bytes)
 * @returns {Promise<boolean>} true if successful
 */
export async function savePSK(agentId, pskBase64) {
  try {
    const db = await openKeyDB();
    if (!db) return false;

    const key = PSK_PREFIX + agentId;
    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(pskBase64, key);

        req.onsuccess = () => resolve(true);
        req.onerror = () => {
          console.warn('[key-store] Failed to write PSK for agent:', agentId, req.error?.message || req.error);
          resolve(false);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(false);
      }
    });
  } catch (e) {
    console.warn('[key-store] savePSK failed:', e?.message || e);
    return false;
  }
}

/**
 * Load agent's Ed25519 public key from IndexedDB.
 * Used for verifying agent_static_pub and enc_hello signatures.
 * @param {string} agentId - Agent ID
 * @returns {Promise<string|null>} base64 string of public key (32 bytes) or null
 */
export async function loadAgentSignPub(agentId) {
  try {
    const db = await openKeyDB();
    if (!db) return null;

    const key = AGENT_SIGN_PUB_PREFIX + agentId;
    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(key);

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => {
          console.warn('[key-store] Failed to read agent sign pub for:', agentId, req.error?.message || req.error);
          resolve(null);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(null);
      }
    });
  } catch (e) {
    console.warn('[key-store] loadAgentSignPub failed:', e?.message || e);
    return null;
  }
}

/**
 * Save agent's Ed25519 public key to IndexedDB.
 * Used for verifying agent_static_pub and enc_hello signatures.
 * @param {string} agentId - Agent ID
 * @param {string} agentSignPubBase64 - base64 string of public key (32 bytes)
 * @returns {Promise<boolean>} true if successful
 */
export async function saveAgentSignPub(agentId, agentSignPubBase64) {
  try {
    const db = await openKeyDB();
    if (!db) return false;

    const key = AGENT_SIGN_PUB_PREFIX + agentId;
    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(agentSignPubBase64, key);

        req.onsuccess = () => resolve(true);
        req.onerror = () => {
          console.warn('[key-store] Failed to write agent sign pub for:', agentId, req.error?.message || req.error);
          resolve(false);
        };
      } catch (e) {
        console.warn('[key-store] Transaction error:', e?.message || e);
        resolve(false);
      }
    });
  } catch (e) {
    console.warn('[key-store] saveAgentSignPub failed:', e?.message || e);
    return false;
  }
}
