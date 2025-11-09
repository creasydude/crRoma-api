'use strict';

const express = require('express');
const router = express.Router();

const { requireAuth, verifyCsrf } = require('../middleware/requireAuth');
const { createKey, revokeKey } = require('../models/apiKeys');
const { logAudit } = require('../models/audits');

// POST /keys/create
router.post('/create', requireAuth, verifyCsrf, (req, res) => {
  const userId = Number(req.user.id);
  const label = (req.body.label || '').trim() || null;

  const result = createKey(userId, label);
  if (!result.ok) {
    return res.status(500).send('Failed to create API key. Please try again.');
  }

  // Audit: key created
  logAudit(userId, 'key_create', { prefix: result.prefix, label });

  // Render a dedicated page showing the full key once
  return res.render('key-created', {
    title: 'API Key Created',
    apiKey: result.key,
    prefix: result.prefix,
    csrfToken: res.locals.csrfToken
  });
});

// POST /keys/:id/revoke
router.post('/:id/revoke', requireAuth, verifyCsrf, (req, res) => {
  const userId = Number(req.user.id);
  const keyId = Number(req.params.id);
  if (!Number.isFinite(keyId) || keyId <= 0) {
    logAudit(userId, 'key_revoke_fail', { reason: 'invalid_id', keyId });
    return res.status(400).send('Invalid key id');
  }

  const r = revokeKey(userId, keyId);
  if (!r.ok) {
    if (r.reason === 'not_found') {
      logAudit(userId, 'key_revoke_fail', { reason: 'not_found', keyId });
      return res.status(404).send('Key not found');
    }
    logAudit(userId, 'key_revoke_fail', { reason: r.reason || 'unknown', keyId });
    return res.status(400).send('Unable to revoke key');
  }

  logAudit(userId, 'key_revoke', { keyId });
  return res.redirect('/dashboard');
});

module.exports = router;