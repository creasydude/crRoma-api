'use strict';

const { run, getOne, all, transact, nowUtc } = require('../db');
const { generateSalt, scryptHash, verifyHash, generateOtpCode } = require('../utils/crypto');
const { isProduction } = require('../config');

const lastOtpCache = new Map();

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

const OTP_TTL_MINUTES = 10;
const OTP_MAX_ATTEMPTS = 0;        // attempts disabled
const OTP_MIN_RESEND_SECONDS = 120; // 1 per 2 minutes per email
const OTP_MAX_PER_HOUR = 5;        // 5 per hour per email

function canSendOtp(email) {
  const now = nowUtc();
  const nowMs = now.getTime();
  const nowIso = now.toISOString();

  const last = getOne(
    'SELECT id, last_sent_at FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1',
    [email]
  );
  if (last && last.last_sent_at) {
    const lastMs = new Date(last.last_sent_at).getTime();
    const waitMs = OTP_MIN_RESEND_SECONDS * 1000 - (nowMs - lastMs);
    if (waitMs > 0) {
      return { ok: false, reason: 'rate_minute', waitSeconds: Math.ceil(waitMs / 1000) };
    }
  }

  const hourAgoIso = new Date(nowMs - 60 * 60 * 1000).toISOString();
  const countRow = getOne(
    'SELECT COUNT(*) AS c FROM otps WHERE email = ? AND created_at >= ?',
    [email, hourAgoIso]
  );
  const count = countRow ? Number(countRow.c || 0) : 0;
  if (count >= OTP_MAX_PER_HOUR) {
    return { ok: false, reason: 'rate_hour' };
  }

  return { ok: true, nowIso };
}

function issueOtp(email) {
  const check = canSendOtp(email);
  if (!check.ok) return { ok: false, ...check };

  const code = generateOtpCode();
  const salt = generateSalt(16);
  const hash = scryptHash(code, salt);
  const now = nowUtc();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + OTP_TTL_MINUTES * 60 * 1000).toISOString();

  let insertedId = null;
  transact(() => {
    run(
      'INSERT INTO otps (email, code_hash, salt, expires_at, last_sent_at) VALUES (?, ?, ?, ?, ?)',
      [email, hash, salt, expiresAt, nowIso]
    );
    const row = getOne('SELECT id FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1', [email]);
    insertedId = row ? row.id : null;
  });

  lastOtpCache.set(email, { code, expiresAt });
  if (!isProduction()) { try { console.warn(`[DEBUG] OTP issued for ${email}: ${code}`); } catch (_) {} }
  return { ok: true, email, code, expiresAt, id: insertedId };
}

function verifyOtp(email, code) {
  const records = all(
    'SELECT id, code_hash, salt, expires_at FROM otps WHERE email = ? AND consumed_at IS NULL ORDER BY id DESC LIMIT 10',
    [email]
  );
  if (!isProduction()) { try { console.warn(`[DEBUG] OTP verify candidates for ${email}: ${records ? records.length : 0}`); } catch (_) {} }
  if (!records || records.length === 0) {
    return { ok: false, reason: 'not_found' };
  }

  const now = nowUtc();
  const nowIso = now.toISOString();

  let matched = null;
  for (const r of records) {
    if (r.expires_at && new Date(r.expires_at).getTime() < now.getTime()) {
      continue;
    }
    const expected = toAsciiString(r.code_hash);
    const attempt = scryptHash(code, r.salt);
    if (!isProduction()) { try { console.warn(`[DEBUG] OTP compare attempt=${attempt.slice(0,12)} expected=${expected.slice(0,12)}`); } catch (_) {} }
    if (attempt === expected || verifyHash(code, r.salt, expected)) {
      matched = r;
      break;
    }
  }

  // Dev-only fallback to in-memory cache (helps diagnose persistence/type issues)
  if (!matched && !isProduction()) {
    const cached = lastOtpCache.get(email);
    if (cached && cached.code === code) {
      matched = records[0];
      try { console.warn('[DEBUG] OTP dev fallback matched via cache'); } catch (_) {}
    }
  }

  if (!matched) {
    return { ok: false, reason: 'invalid_code' };
  }

  // Mark the matching OTP as consumed
  transact(() => {
    run('UPDATE otps SET consumed_at = ? WHERE id = ?', [nowIso, matched.id]);
  });

  return { ok: true, id: matched.id };
}

module.exports = {
  OTP_TTL_MINUTES,
  OTP_MAX_ATTEMPTS,
  OTP_MIN_RESEND_SECONDS,
  OTP_MAX_PER_HOUR,
  canSendOtp,
  issueOtp,
  verifyOtp
};