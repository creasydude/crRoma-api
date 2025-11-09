'use strict';

const express = require('express');
const router = express.Router();

const { verifyCsrf } = require('../middleware/requireAuth');
const { sendOtpEmail } = require('../utils/email');
const { issueOtp, verifyOtp, OTP_TTL_MINUTES } = require('../models/otps');
const { findOrCreateUserByEmail, updateLastLogin } = require('../models/users');
const { setSessionCookie, clearSessionCookie } = require('../utils/jwt');
const { logAudit } = require('../models/audits');

function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const e = email.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

function normalizeDigits(input) {
  let s = typeof input === 'string' ? input : String(input || '');
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    // ASCII 0-9
    if (cp >= 0x30 && cp <= 0x39) { out += ch; continue; }
    // Arabic-Indic ٠-٩
    if (cp >= 0x0660 && cp <= 0x0669) { out += String(cp - 0x0660); continue; }
    // Extended Arabic-Indic ۰-۹ (Persian)
    if (cp >= 0x06F0 && cp <= 0x06F9) { out += String(cp - 0x06F0); continue; }
    // ignore other chars
  }
  return out;
}

function sanitizeOtp(input) {
  const digits = normalizeDigits(input);
  return digits.replace(/\D+/g, '').slice(0, 6);
}

function isValidOtp(code) {
  const c = sanitizeOtp(code);
  return c.length === 6;
}

function normalizeNext(next) {
  if (!next || typeof next !== 'string') return '/dashboard';
  try {
    const n = decodeURIComponent(next);
    // Only allow relative paths, prevent open redirect
    if (n.startsWith('/') && !n.startsWith('//')) return n;
    return '/dashboard';
  } catch (_) {
    return '/dashboard';
  }
}

// GET /auth/login
router.get('/login', (req, res) => {
  const next = req.query.next || '/dashboard';
  res.render('login', {
    title: 'Sign up / Login',
    next,
    csrfToken: res.locals.csrfToken,
    error: null,
    info: null
  });
});

// POST /auth/login (request OTP)
router.post('/login', verifyCsrf, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const next = normalizeNext(req.body.next || req.query.next);

  if (!isValidEmail(email)) {
    return res.status(400).render('login', {
      title: 'Login',
      next,
      csrfToken: res.locals.csrfToken,
      error: 'Please enter a valid email address.',
      info: null
    });
  }

  try {
    const result = issueOtp(email);
    if (!result.ok) {
      let msg = 'Unable to send OTP. Please try again later.';
      if (result.reason === 'rate_minute') {
        msg = `Too many requests. Please wait ${result.waitSeconds}s and try again.`;
      } else if (result.reason === 'rate_hour') {
        msg = 'Too many OTP requests in the last hour. Please try again later.';
      }
      // Audit: OTP send blocked (rate limit or other)
      logAudit(null, 'otp_send_block', { email, reason: result.reason, waitSeconds: result.waitSeconds });
      return res.status(429).render('login', {
        title: 'Login',
        next,
        csrfToken: res.locals.csrfToken,
        error: msg,
        info: null
      });
    }

    // Send email
    const mail = await sendOtpEmail(email, result.code);
    // Audit: OTP sent (include debug flag if using debug transport)
    logAudit(null, 'otp_send', { email, debug: !!(mail && mail.debug) });

    // Render verify page with prefilled email
    const infoMsg = mail && mail.debug && mail.code
      ? `DEBUG: OTP for ${email} is ${mail.code}`
      : 'We have emailed you a 6-digit OTP code. You can request a new code after 2 minutes if needed.';
    return res.render('verify', {
      title: 'Verify OTP',
      email,
      next,
      csrfToken: res.locals.csrfToken,
      ttlMinutes: OTP_TTL_MINUTES,
      error: null,
      info: infoMsg
    });
  } catch (err) {
    console.error('Error sending OTP email:', err);
    // Audit: OTP send error
    logAudit(null, 'otp_send_error', { email, error: err.message });
    return res.status(500).render('login', {
      title: 'Login',
      next,
      csrfToken: res.locals.csrfToken,
      error: 'Internal error while sending OTP. Please try again.',
      info: null
    });
  }
});

// GET /auth/verify
router.get('/verify', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  const next = normalizeNext(req.query.next);

  if (!isValidEmail(email)) {
    return res.redirect(`/auth/login?next=${encodeURIComponent(next || '/dashboard')}`);
  }

  res.render('verify', {
    title: 'Verify OTP',
    email,
    next,
    csrfToken: res.locals.csrfToken,
    ttlMinutes: OTP_TTL_MINUTES,
    error: null,
    info: null
  });
});

// POST /auth/verify
router.post('/verify', verifyCsrf, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const rawCode = (req.body.code || '').toString();
  const code = sanitizeOtp(rawCode);
  const next = normalizeNext(req.body.next || req.query.next);

  if (!isValidEmail(email)) {
    return res.status(400).render('verify', {
      title: 'Verify OTP',
      email,
      next,
      csrfToken: res.locals.csrfToken,
      ttlMinutes: OTP_TTL_MINUTES,
      error: 'Invalid email.',
      info: null
    });
  }
  if (!isValidOtp(code)) {
    return res.status(400).render('verify', {
      title: 'Verify OTP',
      email,
      next,
      csrfToken: res.locals.csrfToken,
      ttlMinutes: OTP_TTL_MINUTES,
      error: 'OTP must be a 6-digit numeric code.',
      info: null
    });
  }

  try {
    const verified = verifyOtp(email, code);
    if (!verified.ok) {
      let msg = 'Incorrect code. Please try again or request a new OTP.';
      if (verified.reason === 'expired') msg = 'OTP expired. Please request a new code.';
      if (verified.reason === 'not_found') msg = 'No active OTP found. Please request a new code.';

      // Audit: OTP verify failed
      logAudit(null, 'otp_verify_fail', { email, reason: verified.reason });
      return res.status(400).render('verify', {
        title: 'Verify OTP',
        email,
        next,
        csrfToken: res.locals.csrfToken,
        ttlMinutes: OTP_TTL_MINUTES,
        error: msg,
        info: null
      });
    }

    // Create or lookup user and set session
    const user = findOrCreateUserByEmail(email);
    updateLastLogin(user.id);
    const jwt = require('../utils/jwt');
    const token = jwt.signSessionToken(user.id, email);
    jwt.setSessionCookie(res, token);
    // Audit: OTP verify success
    logAudit(user.id, 'otp_verify', { email });

    return res.redirect(next || '/dashboard');
  } catch (err) {
    console.error('Error verifying OTP:', err);
    return res.status(500).render('verify', {
      title: 'Verify OTP',
      email,
      next,
      csrfToken: res.locals.csrfToken,
      ttlMinutes: OTP_TTL_MINUTES,
      error: 'Internal error while verifying OTP. Please try again.',
      info: null
    });
  }
});

// GET /auth/logout
router.get('/logout', (req, res) => {
  if (req.user && req.user.id) {
    logAudit(req.user.id, 'logout', null);
  }
  clearSessionCookie(res);
  res.redirect('/');
});

module.exports = router;