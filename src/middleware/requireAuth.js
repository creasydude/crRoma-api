'use strict';

// Middleware: require authenticated dashboard session
function requireAuth(req, res, next) {
  if (req.user) return next();
  const nextUrl = encodeURIComponent(req.originalUrl || '/dashboard');
  return res.redirect(`/auth/login?next=${nextUrl}`);
}

// Middleware: basic double-submit CSRF validation for mutating requests
function verifyCsrf(req, res, next) {
  const method = (req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }
  const cookieToken = (req.cookies && req.cookies['csrf_token']) || '';
  const formToken = (req.body && (req.body._csrf || req.body.csrf || req.body.csrf_token)) ||
                    req.get('x-csrf-token') || req.get('csrf-token') || '';
  if (!cookieToken || !formToken || cookieToken !== formToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  return next();
}

module.exports = {
  requireAuth,
  verifyCsrf
};