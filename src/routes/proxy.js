'use strict';

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const qs = require('querystring');
const http = require('http');
const https = require('https');
const { URL } = require('url');
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
  xfwd: true,
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
    // DEBUG: proxy request metadata
    try {
      const ctype = req.get('content-type') || req.headers['content-type'] || '';
      const clen = req.get('content-length') || req.headers['content-length'] || '';
      const hasBody = req.body && typeof req.body === 'object' ? Object.keys(req.body).length : 0;
      console.log('DEBUG proxy onProxyReq method=%s url=%s ct=%s clenH=%s hasBodyKeys=%s', (req.method||'').toUpperCase(), req.originalUrl || req.url, ctype, clen, hasBody);
    } catch (_) {}

    // Re-stream parsed body (Express json/urlencoded) to upstream so POST/PUT/PATCH are not empty
    const method = (req.method || 'GET').toUpperCase();
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        const contentTypeRaw = req.get('content-type') || req.headers['content-type'] || '';
        const contentType = String(contentTypeRaw).toLowerCase();
        let bodyBuf = null;

        if (contentType.includes('application/json')) {
          try { bodyBuf = Buffer.from(JSON.stringify(req.body)); } catch (_) {}
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          try { bodyBuf = Buffer.from(qs.stringify(req.body)); } catch (_) {}
        }

        if (bodyBuf && bodyBuf.length > 0) {
          try {
            // reset potentially conflicting headers before setting our own
            try { proxyReq.removeHeader('content-length'); } catch (_) {}
            try { proxyReq.removeHeader('transfer-encoding'); } catch (_) {}
            try { proxyReq.removeHeader('expect'); } catch (_) {}

            proxyReq.setHeader('content-type', contentType || 'application/json');
            proxyReq.setHeader('content-length', bodyBuf.length);
            proxyReq.write(bodyBuf);
            // Explicitly end because the original req stream was already consumed by body parsers
            try { proxyReq.end(); } catch (_) {}
          } catch (_) {}
        }
      }
    }
  },
  onProxyRes: (proxyRes, req, res) => {
    // Minimal pass-through; annotate response with user id
    const userId = req.authProxy && req.authProxy.userId ? String(req.authProxy.userId) : '';
    if (userId) res.setHeader('x-authproxy-user', userId);
  },
  onError: (err, req, res) => {
    try {
      const code = (err && err.code) ? String(err.code) : 'proxy_error';
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Upstream proxy error', code }));
    } catch (_) {}
  }
});

/**
 * Manual forward for requests with JSON or x-www-form-urlencoded bodies.
 * This bypasses http-proxy streaming quirks when bodies were parsed by Express.
 */
function forwardBody(req, res, next) {
  try {
    const method = String(req.method || 'GET').toUpperCase();
    // Only handle methods that may have a body
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return proxy(req, res, next);
    }

    const originalUrl = req.originalUrl || req.url || '/';
    const ctypeRaw = req.get('content-type') || req.headers['content-type'] || '';
    const ctype = String(ctypeRaw).toLowerCase();
    const isJson = ctype.includes('application/json');
    const isForm = ctype.includes('application/x-www-form-urlencoded');

    if (!isJson && !isForm) {
      // Defer to the proxy for other body types
      return proxy(req, res, next);
    }

    // Build body string from already-parsed req.body
    let bodyStr = '';
    if (req.body && typeof req.body === 'object') {
      try {
        bodyStr = isJson ? JSON.stringify(req.body) : qs.stringify(req.body);
      } catch (e) {
        bodyStr = '';
      }
    }

    const targetUrl = new URL(originalUrl, config.internalApiBase);
    const isHttps = targetUrl.protocol === 'https:';

    // Build upstream request options
    const headers = Object.assign({}, req.headers);
    // Normalize/override headers for upstream
    delete headers['x-api-key'];
    delete headers['X-API-Key'];
    delete headers['host'];
    delete headers['content-length'];
    delete headers['transfer-encoding'];
    headers['content-type'] = ctypeRaw || (isJson ? 'application/json' : 'application/x-www-form-urlencoded');
    headers['content-length'] = Buffer.byteLength(bodyStr);
    headers['x-real-ip'] = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    const opts = {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      method,
      headers
    };

    // DEBUG
    try {
      console.log('DEBUG forwardBody -> %s %s host=%s ct=%s len=%s', method, opts.path, opts.hostname + ':' + opts.port, headers['content-type'], headers['content-length']);
    } catch (_) {}

    const transport = isHttps ? https : http;
    const upstreamReq = transport.request(opts, (upstreamRes) => {
      // Propagate status and headers
      res.statusCode = upstreamRes.statusCode || 502;
      const respHeaders = upstreamRes.headers || {};
      for (const k in respHeaders) {
        if (!Object.prototype.hasOwnProperty.call(respHeaders, k)) continue;
        if (k.toLowerCase() === 'transfer-encoding') continue; // avoid TE issues
        try { res.setHeader(k, respHeaders[k]); } catch (_) {}
      }
      // annotate with user id
      const userId = req.authProxy && req.authProxy.userId ? String(req.authProxy.userId) : '';
      if (userId) res.setHeader('x-authproxy-user', userId);

      // Pipe upstream response back to client
      upstreamRes.on('error', (err) => {
        try { console.error('DEBUG forwardBody upstreamRes error:', err && err.message); } catch (_) {}
        if (!res.headersSent) {
          res.statusCode = 502;
          res.setHeader('content-type', 'application/json');
          return res.end(JSON.stringify({ error: 'Upstream response error' }));
        }
        try { res.destroy(err); } catch (_) {}
      });
      upstreamRes.pipe(res);
    });

    upstreamReq.setTimeout(60000, () => {
      try { upstreamReq.destroy(new Error('upstream timeout')); } catch (_) {}
    });

    upstreamReq.on('error', (err) => {
      try { console.error('DEBUG forwardBody upstreamReq error:', err && err.message); } catch (_) {}
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader('content-type', 'application/json');
        return res.end(JSON.stringify({ error: 'Upstream request error' }));
      }
      try { res.destroy(err); } catch (_) {}
    });

    // Write body and end
    if (headers['content-length'] > 0) {
      upstreamReq.write(bodyStr);
    }
    upstreamReq.end();
  } catch (e) {
    try { console.error('DEBUG forwardBody fatal:', e && e.message); } catch (_) {}
    res.statusCode = 502;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'Proxy forwarding error' }));
  }
}

// Route JSON/form bodies through manual forwarder first
router.post('*', proxyAuthGuard, forwardBody);
router.put('*', proxyAuthGuard, forwardBody);
router.patch('*', proxyAuthGuard, forwardBody);
router.delete('*', proxyAuthGuard, forwardBody);

// Catch-all: auth guard first, then proxy (handles GET and other methods/content-types)
router.use(proxyAuthGuard, proxy);

module.exports = router;