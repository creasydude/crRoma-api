'use strict';

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const qs = require('querystring');
const { config, blockedInternalDocsPaths, normalizeInternalPath } = require('../config');
const { validateFullKey, touchKeyUsage } = require('../models/apiKeys');
const { incrementToday, isOverLimit, getTodayCount } = require('../models/usage');
const { logAudit } = require('../models/audits');

const router = express.Router();

function secondsUntilNextUtcMidnight(d = new Date()) {
  const next = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0));
  return Math.max(0, Math.floor((next.getTime() - d.getTime()) / 1000));
}

function proxyAuthGuard(req, res, next) {
  const reqPath = normalizeInternalPath(req.path || '/');

  // Block internal docs and openapi endpoints
  if (blockedInternalDocsPaths.has(reqPath)) {
    // Audit: blocked docs access
    logAudit(null, 'proxy_block', { reason: 'docs', path: reqPath });
    return res.status(404).json({ error: 'Not Found' });
  }

  // Header: X-API-Key
  const apiKey = req.get('X-API-Key') || req.get('x-api-key');
  if (!apiKey) {
    // Audit: missing API key
    logAudit(null, 'proxy_block', { reason: 'missing_key', path: reqPath });
    return res.status(401).json({ error: 'Missing X-API-Key header' });
  }

  // Validate key
  const v = validateFullKey(apiKey);
  if (!v.ok) {
    // Audit: invalid API key
    logAudit(null, 'proxy_block', { reason: v.reason || 'invalid_key', path: reqPath });
    return res.status(401).json({ error: 'Invalid API key', reason: v.reason });
  }

  // Daily quota check
  if (isOverLimit(v.userId, config.defaultDailyLimit)) {
    const count = getTodayCount(v.userId);
    const resetSeconds = secondsUntilNextUtcMidnight();
    // Audit: quota block
    logAudit(v.userId, 'proxy_block', { reason: 'quota', count, limit: config.defaultDailyLimit, reset_seconds: resetSeconds, path: reqPath });
    return res.status(429).json({
      error: 'Daily quota exceeded',
      count,
      limit: config.defaultDailyLimit,
      reset_seconds: resetSeconds
    });
  }

  // Increment usage before proxying (counts regardless of upstream outcome)
  incrementToday(v.userId);
  touchKeyUsage(v.keyId);
  // Audit: proxy forwarded
  logAudit(v.userId, 'proxy_hit', { path: reqPath, method: req.method });
  
  // Attach metadata for optional logging
  req.authProxy = { userId: v.userId, keyId: v.keyId, prefix: v.prefix };
  
  next();
}

const proxy = createProxyMiddleware({
  target: config.internalApiBase,
  changeOrigin: true,
  logLevel: 'warn',
  // Give upstream some time; Cloudflare edges typically cap ~100s
  timeout: 120000,
  proxyTimeout: 120000,
  pathRewrite: (path, req) => path,
  onProxyReq: (proxyReq, req, res) => {
    // Strip client API key header before forwarding
    try {
      proxyReq.removeHeader('x-api-key');
      proxyReq.removeHeader('X-API-Key');
    } catch (_) {}

    // Forward real IP (best-effort)
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    proxyReq.setHeader('x-real-ip', ip);

    // Re-stream parsed body (Express json/urlencoded) to upstream so POST/PUT/PATCH are not empty
    const method = (req.method || 'GET').toUpperCase();
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        const contentType = req.get('content-type') || req.headers['content-type'] || '';
        let bodyData = null;

        if (contentType.toLowerCase().includes('application/json')) {
          try { bodyData = JSON.stringify(req.body); } catch (_) {}
        } else if (contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
          try { bodyData = qs.stringify(req.body); } catch (_) {}
        }

        if (bodyData) {
          try {
            proxyReq.setHeader('content-type', contentType || 'application/json');
            proxyReq.setHeader('content-length', Buffer.byteLength(bodyData));
            proxyReq.write(bodyData);
          } catch (_) {}
        }
      }
    }
  },
  onProxyRes: (proxyRes, req, res) => {
    // Minimal pass-through; annotate response with user id
    const userId = req.authProxy && req.authProxy.userId ? String(req.authProxy.userId) : '';
    if (userId) res.setHeader('x-authproxy-user', userId);
  }
});

// Catch-all: auth guard first, then proxy
router.use(proxyAuthGuard, proxy);

module.exports = router;