'use strict';

const { run, nowUtc } = require('../db');

/**
 * Write an audit entry.
 * type examples: 'otp_send', 'otp_verify', 'key_create', 'key_revoke', 'proxy_block', 'proxy_hit'
 * details can be an object or string; objects are JSON-stringified.
 */
function logAudit(userId, type, details = null) {
  if (!type || typeof type !== 'string') return;

  let detailsStr = null;
  if (details !== null && details !== undefined) {
    if (typeof details === 'string') {
      detailsStr = details;
    } else {
      try {
        detailsStr = JSON.stringify(details);
      } catch (_) {
        detailsStr = String(details);
      }
    }
  }

  run(
    'INSERT INTO audits (user_id, type, details) VALUES (?, ?, ?)',
    [userId || null, type, detailsStr]
  );
}

module.exports = {
  logAudit
};