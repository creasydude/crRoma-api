'use strict';

const { run, getOne, all, transact, nowUtc } = require('../db');
const { generateApiKey, verifyHash } = require('../utils/crypto');

// List API keys for a user (without secrets)
function listKeys(userId) {
  return all(
    `SELECT id, key_prefix AS prefix, label, created_at, revoked_at, last_used_at
     FROM api_keys WHERE user_id = ?
     ORDER BY created_at DESC`,
    [userId]
  );
}

// Create a new API key for a user and return the full key once
function createKey(userId, label = null) {
  let attempt = 0;
  let record = null;
  let fullKey = null;

  transact(() => {
    while (attempt < 3) {
      attempt += 1;
      const { key, prefix, salt, hash } = generateApiKey();
      try {
        run(
          `INSERT INTO api_keys (user_id, key_prefix, key_hash, salt, label)
           VALUES (?, ?, ?, ?, ?)`,
          [userId, prefix, hash, salt, label]
        );
        // Fetch inserted row id
        record = getOne(
          `SELECT id, user_id, key_prefix AS prefix, created_at FROM api_keys
           WHERE user_id = ? AND key_prefix = ? ORDER BY id DESC LIMIT 1`,
          [userId, prefix]
        );
        fullKey = key;
        break;
      } catch (e) {
        // Likely unique collision on (user_id, key_prefix); retry
        // If it's another error, rethrow
        if (!/UNIQUE/i.test(String(e && e.message))) throw e;
      }
    }
  });

  if (!record || !fullKey) {
    return { ok: false, reason: 'failed_to_create' };
  }
  return { ok: true, id: record.id, key: fullKey, prefix: record.prefix };
}

// Revoke (delete) an API key (soft-delete by setting revoked_at)
function revokeKey(userId, keyId) {
  const nowIso = nowUtc().toISOString();
  transact(() => {
    run(
      `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
      [nowIso, keyId, userId]
    );
  });
  const row = getOne(
    `SELECT id, revoked_at FROM api_keys WHERE id = ? AND user_id = ?`,
    [keyId, userId]
  );
  if (!row) return { ok: false, reason: 'not_found' };
  if (!row.revoked_at) return { ok: false, reason: 'not_revoked' };
  return { ok: true };
}

// Update last_used_at for a key
function touchKeyUsage(keyId) {
  const nowIso = nowUtc().toISOString();
  run(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, [nowIso, keyId]);
}

// Lookup active key row by prefix
function findActiveByPrefix(prefix) {
  return getOne(
    `SELECT id, user_id, key_prefix AS prefix, key_hash, salt, revoked_at
     FROM api_keys
     WHERE key_prefix = ? AND revoked_at IS NULL
     ORDER BY id DESC LIMIT 1`,
    [prefix]
  );
}

// Validate a user-provided full API key string "prefix.secret"
function validateFullKey(fullKey) {
  if (typeof fullKey !== 'string' || fullKey.length < 12) {
    return { ok: false, reason: 'format' };
  }
  const dotIdx = fullKey.indexOf('.');
  if (dotIdx <= 0) return { ok: false, reason: 'format' };
  const prefix = fullKey.slice(0, dotIdx);

  const row = findActiveByPrefix(prefix);
  if (!row) return { ok: false, reason: 'not_found' };

  const valid = verifyHash(fullKey, row.salt, row.key_hash);
  if (!valid) return { ok: false, reason: 'mismatch' };

  return { ok: true, keyId: row.id, userId: row.user_id, prefix: row.prefix };
}

module.exports = {
  listKeys,
  createKey,
  revokeKey,
  touchKeyUsage,
  findActiveByPrefix,
  validateFullKey
};