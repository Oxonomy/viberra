/**
 * Concatenate multiple Uint8Arrays
 * @param  {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
function concat(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Derives directional session keys from PSK and room_id
 * @param {Object} S - sodium module
 * @param {Uint8Array} psk - Pre-shared key (32 bytes)
 * @param {string} roomId - Room ID
 * @returns {{ keyA2C: Uint8Array, keyC2A: Uint8Array, noncePrefixA2C: Uint8Array, noncePrefixC2A: Uint8Array }}
 */
export function deriveSessionKeys(S, psk, roomId) {
  const roomIdBuf = S.from_string(roomId);

  // Key agent → client
  const keyA2C = S.crypto_generichash(
    32,
    concat(psk, S.from_string('viberra-webrtc-a2c-v1'), roomIdBuf)
  );

  // Key client → agent
  const keyC2A = S.crypto_generichash(
    32,
    concat(psk, S.from_string('viberra-webrtc-c2a-v1'), roomIdBuf)
  );

  // Nonce prefixes (16 bytes)
  const noncePrefixA2C = S.crypto_generichash(
    16,
    concat(psk, S.from_string('nonce-a2c'), roomIdBuf)
  );

  const noncePrefixC2A = S.crypto_generichash(
    16,
    concat(psk, S.from_string('nonce-c2a'), roomIdBuf)
  );

  return { keyA2C, keyC2A, noncePrefixA2C, noncePrefixC2A };
}

/**
 * Encrypts chunk with crypto_secretbox
 * @param {Object} S - sodium module
 * @param {Object} encState - object with fields keySend, noncePrefixSend, sendCounter
 * @param {Uint8Array} plainBuf - data to encrypt
 * @returns {Uint8Array} encrypted buffer
 */
export function encryptChunk(S, encState, plainBuf) {
  // Nonce = noncePrefix(16) + counter(8) BigEndian
  const counterBuf = new Uint8Array(8);
  const view = new DataView(counterBuf.buffer);
  view.setBigUint64(0, encState.sendCounter, false); // BigEndian = false

  const nonce = concat(encState.noncePrefixSend, counterBuf);

  encState.sendCounter += 1n;

  const cipher = S.crypto_secretbox_easy(plainBuf, nonce, encState.keySend);
  return new Uint8Array(cipher);
}

/**
 * Decrypts chunk with crypto_secretbox_open_easy
 * @param {Object} S - sodium module
 * @param {Object} encState - object with fields keyRecv, noncePrefixRecv, recvCounter
 * @param {Uint8Array} cipherBuf - encrypted data
 * @returns {Uint8Array} decrypted buffer or throw
 * @throws {Error} if decryption failed (wrong key, MAC, nonce)
 */
export function decryptChunk(S, encState, cipherBuf) {
  const counterBuf = new Uint8Array(8);
  const view = new DataView(counterBuf.buffer);
  view.setBigUint64(0, encState.recvCounter, false); // BigEndian = false

  const nonce = concat(encState.noncePrefixRecv, counterBuf);

  try {
    const plain = S.crypto_secretbox_open_easy(cipherBuf, nonce, encState.keyRecv);
    encState.recvCounter += 1n;
    return new Uint8Array(plain);
  } catch (e) {
    throw new Error('E2EE decryption failed: ' + (e?.message || e));
  }
}
