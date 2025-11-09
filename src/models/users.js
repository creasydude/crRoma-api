'use strict';

const { run, getOne, transact, nowUtc } = require('../db');

function getUserByEmail(email) {
  return getOne('SELECT * FROM users WHERE email = ?', [email]);
}

function getUserById(id) {
  return getOne('SELECT * FROM users WHERE id = ?', [id]);
}

function createUser(email) {
  return transact(() => {
    run('INSERT INTO users (email) VALUES (?)', [email]);
    return getUserByEmail(email);
  });
}

function findOrCreateUserByEmail(email) {
  const existing = getUserByEmail(email);
  if (existing) return existing;
  return createUser(email);
}

function updateLastLogin(userId) {
  const nowIso = nowUtc().toISOString();
  run('UPDATE users SET last_login_at = ? WHERE id = ?', [nowIso, userId]);
  return getUserById(userId);
}

module.exports = {
  getUserByEmail,
  getUserById,
  createUser,
  findOrCreateUserByEmail,
  updateLastLogin
};