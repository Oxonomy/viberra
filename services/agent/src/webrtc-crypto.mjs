import { Buffer } from 'node:buffer';

/**
 * Derives directional session keys from PSK and room_id
 * @param {Object} S - sodium module
 * @param {Buffer} psk - Pre-shared key (32 bytes)
 * @param {string} roomId - Room ID
 * @returns {{ keyA2C: Buffer, keyC2A: Buffer, noncePrefixA2C: Buffer, noncePrefixC2A: Buffer }}
 */
export function deriveSessionKeys(S, psk, roomId) {
  const roomIdBuf = Buffer.from(roomId, 'utf8');

  // Key agent → client
  const keyA2C = Buffer.from(
    S.crypto_generichash(
      32,
      Buffer.concat([psk, Buffer.from('viberra-webrtc-a2c-v1', 'utf8'), roomIdBuf])
    )
  );

  // Key client → agent
  const keyC2A = Buffer.from(
    S.crypto_generichash(
      32,
      Buffer.concat([psk, Buffer.from('viberra-webrtc-c2a-v1', 'utf8'), roomIdBuf])
    )
  );

  // Nonce prefixes (16 bytes)
  const noncePrefixA2C = Buffer.from(
    S.crypto_generichash(
      16,
      Buffer.concat([psk, Buffer.from('nonce-a2c', 'utf8'), roomIdBuf])
    )
  );

  const noncePrefixC2A = Buffer.from(
    S.crypto_generichash(
      16,
      Buffer.concat([psk, Buffer.from('nonce-c2a', 'utf8'), roomIdBuf])
    )
  );

  return { keyA2C, keyC2A, noncePrefixA2C, noncePrefixC2A };
}

/**
 * Encrypts chunk with crypto_secretbox
 * @param {Object} S - sodium module
 * @param {Object} encState - runtime.enc with fields keySend, noncePrefixSend, sendCounter
 * @param {Buffer} plainBuf - data to encrypt
 * @returns {Buffer} encrypted buffer
 */
export function encryptChunk(S, encState, plainBuf) {
  // Nonce = noncePrefix(16) + counter(8) BigEndian
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(encState.sendCounter);
  const nonce = Buffer.concat([encState.noncePrefixSend, counterBuf]);

  encState.sendCounter += 1n;

  const cipher = S.crypto_secretbox_easy(plainBuf, nonce, encState.keySend);
  return Buffer.from(cipher);
}

/**
 * Decrypts chunk with crypto_secretbox_open_easy
 * @param {Object} S - sodium module
 * @param {Object} encState - runtime.enc with fields keyRecv, noncePrefixRecv, recvCounter
 * @param {Buffer} cipherBuf - encrypted data
 * @returns {Buffer} decrypted buffer or throw
 * @throws {Error} if decryption failed (wrong key, MAC, nonce)
 */
export function decryptChunk(S, encState, cipherBuf) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(encState.recvCounter);
  const nonce = Buffer.concat([encState.noncePrefixRecv, counterBuf]);

  try {
    const plain = S.crypto_secretbox_open_easy(cipherBuf, nonce, encState.keyRecv);
    encState.recvCounter += 1n;
    return Buffer.from(plain);
  } catch (e) {
    throw new Error('E2EE decryption failed: ' + (e?.message || e));
  }
}
