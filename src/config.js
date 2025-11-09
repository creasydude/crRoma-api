'use strict';

const fs = require('fs');
const path = require('path');

require('dotenv').config();

function getEnv(name, defaultValue = undefined) {
  const val = process.env[name];
  return val !== undefined && val !== '' ? val : defaultValue;
}

function toInt(val, defaultInt) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) ? n : defaultInt;
}

const config = {
  nodeEnv: getEnv('NODE_ENV', 'production'),
  port: toInt(getEnv('PORT'), 443),
  redirectPort: getEnv('HTTP_REDIRECT_PORT') ? toInt(getEnv('HTTP_REDIRECT_PORT'), 0) : null,
  siteBaseUrl: getEnv('SITE_BASE_URL', 'https://example.com'),
  tls: {
    certPath: getEnv('HTTPS_CERT_PATH', ''),
    keyPath: getEnv('HTTPS_KEY_PATH', '')
  },
  internalApiBase: getEnv('INTERNAL_API_BASE', 'http://127.0.0.1:8000'),
  // Legacy SMTP settings (kept for compatibility; not used with Mailtrap API)
  smtp: {
    host: getEnv('SMTP_HOST', 'smtp.mailtrap.io'),
    port: toInt(getEnv('SMTP_PORT'), 587),
    user: getEnv('SMTP_USER', ''),
    pass: getEnv('SMTP_PASS', ''),
    from: getEnv('SMTP_FROM', 'ROMA Proxy <no-reply@example.com>')
  },
  // Official Mailtrap API settings
  mailtrap: {
    token: getEnv('MAILTRAP_TOKEN', ''),
    senderEmail: getEnv('MAILTRAP_SENDER_EMAIL', ''),
    senderName: getEnv('MAILTRAP_SENDER_NAME', 'ROMA Auth Proxy')
  },
  jwtSecret: getEnv('JWT_SECRET', 'change-this-in-production'),
  defaultDailyLimit: toInt(getEnv('DEFAULT_DAILY_LIMIT'), 50)
};

function validateConfig(cfg) {
  const errors = [];
  if (!cfg.tls.certPath || !cfg.tls.keyPath) {
    errors.push('HTTPS_CERT_PATH and HTTPS_KEY_PATH must be set');
  } else {
    if (!fs.existsSync(cfg.tls.certPath)) errors.push(`TLS cert not found at ${cfg.tls.certPath}`);
    if (!fs.existsSync(cfg.tls.keyPath)) errors.push(`TLS key not found at ${cfg.tls.keyPath}`);
  }

  if (!/^https?:\/\//.test(cfg.internalApiBase)) {
    errors.push('INTERNAL_API_BASE must start with http:// or https://');
  }

  if (!cfg.jwtSecret || cfg.jwtSecret === 'change-this-in-production') {
    console.warn('WARNING: Use a strong JWT_SECRET in production');
  }

  if (cfg.nodeEnv === 'production' && (!cfg.mailtrap || !cfg.mailtrap.token)) {
    console.warn('WARNING: MAILTRAP_TOKEN is not set; OTP emails will use debug mode and will not be delivered.');
  }

  if (cfg.defaultDailyLimit <= 0) {
    errors.push('DEFAULT_DAILY_LIMIT must be positive');
  }

  return errors;
}

const validationErrors = validateConfig(config);

const blockedInternalDocsPaths = new Set(['/openapi.json', '/docs', '/redoc']);

function normalizeInternalPath(reqPath) {
  return reqPath.startsWith('/') ? reqPath : `/${reqPath}`;
}

function isProduction() {
  return config.nodeEnv === 'production';
}

module.exports = {
  config,
  validationErrors,
  blockedInternalDocsPaths,
  normalizeInternalPath,
  isProduction
};