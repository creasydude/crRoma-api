'use strict';

const jwt = require('jsonwebtoken');
const { config, isProduction } = require('../config');

const SESSION_COOKIE = 'session';
const SESSION_TTL_DAYS = 7;
const SESSION_MAX_AGE_MS = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;

function signSessionToken(userId, email) {
  const payload = {
    sub: String(userId),
    email,
    typ: 'session'
  };
  const token = jwt.sign(payload, config.jwtSecret, { expiresIn: `${SESSION_TTL_DAYS}d` });
  return token;
}

function verifySessionToken(token) {
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    return decoded;
  } catch (_) {
    return null;
  }
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: isProduction(), // true in production (HTTPS)
    sameSite: 'lax',
    maxAge: SESSION_MAX_AGE_MS,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: isProduction(),
    sameSite: 'lax',
    path: '/'
  });
}

function getTokenFromReq(req) {
  return req.cookies ? req.cookies[SESSION_COOKIE] : undefined;
}

module.exports = {
  SESSION_COOKIE,
  signSessionToken,
  verifySessionToken,
  setSessionCookie,
  clearSessionCookie,
  getTokenFromReq
};