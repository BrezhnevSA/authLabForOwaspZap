'use strict';

const { createHmac, timingSafeEqual } = require('node:crypto');

// RFC 4648 base32, RFC 4226 HOTP, RFC 6238 TOTP (SHA-1, 30-second step).
const DEFAULT_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'; // TEST FIXTURE ONLY

function decodeBase32(input) {
  const value = String(input).trim().replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (!value || /[^A-Z2-7]/.test(value)) throw new Error('TOTP_SECRET must be RFC 4648 base32');
  let bits = 0, buffer = 0;
  const out = [];
  for (const char of value) {
    buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  if (out.length < 10) throw new Error('TOTP_SECRET must contain at least 80 bits');
  return Buffer.from(out);
}

function hotp(key, counter, digits = 6) {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('Invalid HOTP counter');
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', key).update(buf).digest();
  const off = mac[mac.length - 1] & 0xf;
  const truncated = (mac.readUInt32BE(off) & 0x7fffffff) % (10 ** digits);
  return String(truncated).padStart(digits, '0');
}

function totp(secret = DEFAULT_SECRET, at = Date.now(), digits = 6) {
  return hotp(decodeBase32(secret), Math.floor(at / 30000), digits);
}

// Returns accepted time-step, or null; reject replayed/older counters.
function verifyTotp(code, secret, at = Date.now(), lastAccepted = -1) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const key = decodeBase32(secret);
  const current = Math.floor(at / 30000);
  for (const shift of [-1, 0, 1]) {
    const counter = current + shift;
    if (counter <= lastAccepted || counter < 0) continue;
    const expected = Buffer.from(hotp(key, counter));
    if (timingSafeEqual(Buffer.from(code), expected)) return counter;
  }
  return null;
}

module.exports = { DEFAULT_SECRET, decodeBase32, hotp, totp, verifyTotp };

if (require.main === module) {
  const secret = process.env.TOTP_SECRET || DEFAULT_SECRET;
  try {
    console.log(totp(secret));
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
