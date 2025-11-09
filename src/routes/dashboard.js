'use strict';

const express = require('express');
const router = express.Router();

const { requireAuth } = require('../middleware/requireAuth');
const { listKeys } = require('../models/apiKeys');
const { getTodayCount } = require('../models/usage');
const { config } = require('../config');

 // GET /dashboard
router.get('/', requireAuth, (req, res) => {
  const userId = Number(req.user.id);
  const keys = listKeys(userId);

  if (process.env.NODE_ENV !== 'production') {
    try { console.log('DEBUG dashboard: userId=%s keys=%j', userId, keys); } catch (_) {}
  }

  const usageToday = getTodayCount(userId);
  const dailyLimit = config.defaultDailyLimit;

  res.render('dashboard', {
    title: 'Dashboard',
    keys,
    usageToday,
    dailyLimit,
    csrfToken: res.locals.csrfToken
  });
});

module.exports = router;