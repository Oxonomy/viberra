// Message type constants
export const CTRL = 0x00;  // Control messages (JSON)
export const PTY  = 0x01;  // PTY data (raw bytes)

// Text encoder/decoder for JSON
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');

/**
 * Frame a control message (JSON object)
 * @param {object} obj - JavaScript object to send as control message
 * @returns {Uint8Array} Framed message with 0x00 prefix
 */
export function frameCtrl(obj) {
  const body = encoder.encode(JSON.stringify(obj));
  const out = new Uint8Array(1 + body.length);
  out[0] = CTRL;
  out.set(body, 1);
  return out;
}

/**
 * Frame PTY data
 * @param {Buffer|ArrayBuffer|TypedArray|string} bufLike - PTY data to frame
 * @returns {Buffer} Framed message with 0x01 prefix
 */
export function framePty(bufLike) {
  const body = toBuffer(bufLike);
  const out = Buffer.concat([Buffer.from([PTY]), body]);
  return out;
}

/**
 * Parse a framed message
 * @param {Buffer|ArrayBuffer|TypedArray} data - Framed message data
 * @returns {object} Parsed result: {type: 'ctrl'|'pty'|'bad-ctrl'|'unknown'|null, json?, buf?}
 */
export function parseFrame(data) {
  const buf = toBuffer(data);
  if (buf.length === 0) return { type: null };

  const tag = buf[0];
  const payload = buf.subarray(1);

  if (tag === CTRL) {
    try {
      const json = JSON.parse(payload.toString('utf8'));
      return { type: 'ctrl', json };
    } catch {
      return { type: 'bad-ctrl' };
    }
  }

  if (tag === PTY) {
    return { type: 'pty', buf: payload };
  }

  return { type: 'unknown' };
}

/**
 * Convert various data types to Buffer
 * @param {*} x - Data to convert
 * @returns {Buffer} Node.js Buffer
 */
export function toBuffer(x) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof ArrayBuffer) return Buffer.from(new Uint8Array(x));
  if (ArrayBuffer.isView(x)) return Buffer.from(x.buffer, x.byteOffset, x.byteLength);
  return Buffer.from(String(x), 'utf8');
}