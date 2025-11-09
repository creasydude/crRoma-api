'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const { config, validationErrors, isProduction } = require('./config');
const { initDb } = require('./db');
const { getTokenFromReq, verifySessionToken } = require('./utils/jwt');

// Routers (to be implemented in subsequent steps)
const authRouter = require('./routes/auth');
const dashboardRouter = require('./routes/dashboard');
const keysRouter = require('./routes/keys');
const proxyRouter = require('./routes/proxy');

function createApp() {
  const app = express();

  // Trust reverse proxies (for correct protocol/ips if behind proxy)
  app.set('trust proxy', 1);

  // Views (EJS)
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));

  // Static assets (optional public dir) and root assets
  app.use('/public', express.static(path.join(__dirname, '..', 'public')));
  app.get('/favicon.ico', (req, res) => {
    const ico = path.join(__dirname, '..', 'favicon.ico');
    if (fs.existsSync(ico)) return res.sendFile(ico);
    res.status(404).end();
  });
  app.get('/logo.jpg', (req, res) => {
    const logo = path.join(__dirname, '..', 'logo.jpg');
    if (fs.existsSync(logo)) return res.sendFile(logo);
    res.status(404).end();
  });
  // Serve robots.txt from public at root path
  app.get('/robots.txt', (req, res) => {
    const robots = path.join(__dirname, '..', 'public', 'robots.txt');
    if (fs.existsSync(robots)) return res.sendFile(robots);
    res.status(404).end();
  });

  // Security headers
  app.use(helmet({
    contentSecurityPolicy: false // keep simple for Tailwind CDN and EJS inline
  }));

  // Logging
  app.use(morgan(isProduction() ? 'combined' : 'dev'));

  // Body parsing and cookies
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(cookieParser());

  // App locals for templates
  app.locals.SITE_BASE_URL = config.siteBaseUrl;
  app.locals.GITHUB_URL = 'https://github.com/creasydude';
  app.locals.DOCS_URL = '/docs';
  app.locals.APP_NAME = 'crROMA API';

   // Attach current user from session cookie (if present)
  app.use((req, res, next) => {
    const token = getTokenFromReq(req);
    const decoded = token ? verifySessionToken(token) : null;
  
    if (decoded && decoded.typ === 'session') {
      const uid = Number(decoded.sub);
      if (Number.isFinite(uid) && uid > 0) {
        req.user = { id: uid, email: decoded.email };
        res.locals.currentUser = req.user;
      } else {
        // Invalid uid in token; treat as unauthenticated
        req.user = null;
        res.locals.currentUser = null;
      }
    } else {
      req.user = null;
      res.locals.currentUser = null;
    }
    next();
  });

  // Lightweight CSRF token generator (double-submit) for HTML forms
  app.use((req, res, next) => {
    let csrf = req.cookies ? req.cookies['csrf_token'] : undefined;
    if (!csrf) {
      csrf = crypto.randomBytes(24).toString('base64url');
      res.cookie('csrf_token', csrf, {
        httpOnly: false,
        secure: isProduction(),
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/'
      });
    }
    res.locals.csrfToken = csrf;
    next();
  });

  // Home
  app.get('/', (req, res) => {
    res.render('home', {
      title: 'ROMA Auth Proxy'
    });
  });

  // Human docs page (not proxied)
  app.get('/docs', (req, res) => {
    res.render('docs', {
      title: 'API Docs'
    });
  });

  // Feature routes
  app.use('/auth', authRouter);
  app.use('/dashboard', dashboardRouter);
  app.use('/keys', keysRouter);

  // Catch-all proxy comes last
  app.use(proxyRouter);

  return app;
}

async function start() {
  // Ensure DB exists and schema is applied
  await initDb();

  // Decide HTTPS vs HTTP
  const tlsConfigured = validationErrors.length === 0;

  // Prefer HTTPS; allow HTTP fallback in non-production if TLS missing
  let useHttps = tlsConfigured;
  let port = config.port || 443;

  if (!useHttps) {
    if (isProduction()) {
      console.error('TLS is not properly configured in production:', validationErrors);
      process.exit(1);
    } else {
      // Development fallback
      if (!port || port === 443) port = 3000;
      console.warn('TLS not configured. Starting HTTP server for development.');
    }
  }

  const app = createApp();

  if (useHttps) {
    const key = fs.readFileSync(config.tls.keyPath);
    const cert = fs.readFileSync(config.tls.certPath);
    https.createServer({ key, cert }, app).listen(port, () => {
      console.log(`HTTPS server listening on https://0.0.0.0:${port}`);
    });

    // Optional HTTP->HTTPS redirect
    if (config.redirectPort) {
      http.createServer((req, res) => {
        const host = req.headers.host || '';
        const targetHost = host.replace(/:\d+$/, `:${port}`);
        const location = `https://${targetHost}${req.url}`;
        res.writeHead(301, { Location: location });
        res.end();
      }).listen(config.redirectPort, () => {
        console.log(`HTTP redirect server listening on http://0.0.0.0:${config.redirectPort} -> HTTPS ${port}`);
      });
    }
  } else {
    http.createServer(app).listen(port, () => {
      console.log(`HTTP server listening on http://0.0.0.0:${port}`);
    });
  }
}

start().catch((err) => {
  console.error('Fatal error starting server:', err);
  process.exit(1);
});