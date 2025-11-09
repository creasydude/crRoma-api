'use strict';

const { run, getOne, transact, toUtcDateStr } = require('../db');
const { config } = require('../config');

function getCountForDate(userId, dateUtc) {
  const row = getOne(
    'SELECT count AS c FROM usage_daily WHERE user_id = ? AND date_utc = ?',
    [userId, dateUtc]
  );
  return row ? Number(row.c || 0) : 0;
}

function incrementForDate(userId, dateUtc) {
  // Upsert: insert with count=1 or update to count+1
  return transact(() => {
    const existing = getOne(
      'SELECT count AS c FROM usage_daily WHERE user_id = ? AND date_utc = ?',
      [userId, dateUtc]
    );
    if (!existing) {
      run(
        'INSERT INTO usage_daily (user_id, date_utc, count) VALUES (?, ?, ?)',
        [userId, dateUtc, 1]
      );
      return 1;
    } else {
      run(
        'UPDATE usage_daily SET count = count + 1 WHERE user_id = ? AND date_utc = ?',
        [userId, dateUtc]
      );
      return Number(existing.c || 0) + 1;
    }
  });
}

function getTodayCount(userId) {
  const date = toUtcDateStr();
  return getCountForDate(userId, date);
}

function incrementToday(userId) {
  const date = toUtcDateStr();
  return incrementForDate(userId, date);
}

function isOverLimit(userId, limit = config.defaultDailyLimit) {
  const count = getTodayCount(userId);
  return count >= Number(limit || 0);
}

module.exports = {
  getCountForDate,
  incrementForDate,
  getTodayCount,
  incrementToday,
  isOverLimit
};