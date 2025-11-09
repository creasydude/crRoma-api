'use strict';

const crypto = require('crypto');

// Generate random salt (base64url)
function generateSalt(bytes = 16) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// Derive a scrypt hash (base64url) with robust salt handling
function scryptHash(plain, salt, keylen = 64) {
  const p = (typeof plain === 'string') ? plain : String(plain);
  let s = salt;
  if (typeof s !== 'string' && !Buffer.isBuffer(s)) {
    if (s && (s instanceof Uint8Array || Array.isArray(s))) {
      s = Buffer.from(s);
    } else if (s && s.buffer && s.byteLength !== undefined) {
      s = Buffer.from(s.buffer, s.byteOffset || 0, s.byteLength);
    } else {
      s = String(s);
    }
  }
  const buf = crypto.scryptSync(p, s, keylen, { N: 16384, r: 8, p: 1 });
  return bufferToBase64url(buf);
}

// Base64url helpers
function toAsciiString(input) {
  if (typeof input === 'string') return input;
  if (Buffer.isBuffer(input)) return input.toString('utf8');
  if (input && (input instanceof Uint8Array || Array.isArray(input))) {
    return Buffer.from(input).toString('utf8');
  }
  if (input && input.buffer && input.byteLength !== undefined) {
    return Buffer.from(input.buffer, input.byteOffset || 0, input.byteLength).toString('utf8');
  }
  return String(input || '');
}

function base64urlToBuffer(s) {
  const str = toAsciiString(s).trim();
  if (!str) return Buffer.alloc(0);
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad) b64 += '='.repeat(4 - pad);
  return Buffer.from(b64, 'base64');
}

function bufferToBase64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Constant-time verification
function verifyHash(plain, salt, expectedBase64url, keylen = 64) {
  const actual = scryptHash(plain, salt, keylen);
  const a = base64urlToBuffer(actual);
  const b = base64urlToBuffer(expectedBase64url);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Generate a 6-digit numeric OTP as string
function generateOtpCode() {
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, '0');
}

// Generate an API key: prefix.secret
// Returns { key, prefix, salt, hash }
function generateApiKey() {
  const prefix = crypto.randomBytes(4).toString('hex'); // 8 hex chars
  const secret = crypto.randomBytes(24).toString('base64url'); // compact + strong
  const key = `${prefix}.${secret}`;
  const salt = generateSalt(16);
  const hash = scryptHash(key, salt);
  return { key, prefix, salt, hash };
}

module.exports = {
  generateSalt,
  scryptHash,
  verifyHash,
  generateOtpCode,
  generateApiKey
};