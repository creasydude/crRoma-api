'use strict';

const fs = require('fs');
const path = require('path');

let SQL = null;       // sql.js module (once initialized)
let db = null;        // sql.js Database instance
let dbReady = null;   // Promise for initialization

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'roma.sqlite');
const SCHEMA_PATH = path.join(__dirname, '..', 'sql', 'schema.sql');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

async function initDb() {
  if (dbReady) return dbReady;

  dbReady = (async () => {
    // Resolve the sql.js initializer and WASM path
    let initSqlJs = require('sql.js');
    if (initSqlJs && initSqlJs.default) initSqlJs = initSqlJs.default;
    const wasmDir = path.dirname(require.resolve('sql.js/dist/sql-wasm.wasm'));

    SQL = await initSqlJs({
      locateFile: (file) => path.join(wasmDir, file)
    });

    ensureDir(DATA_DIR);

    if (fs.existsSync(DB_PATH)) {
      const fileBuffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(fileBuffer);
    } else {
      db = new SQL.Database();
      // Apply schema on first run
      const schemaSql = fs.readFileSync(SCHEMA_PATH, 'utf8');
      db.exec(schemaSql);
      saveDb();
    }

    return db;
  })().catch((err) => {
    console.error('Database initialization failed:', err);
    throw err;
  });

  return dbReady;
}

function getDb() {
  if (!db) throw new Error('Database not initialized. Call initDb() first.');
  return db;
}

function saveDb() {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Execute raw SQL without parameters (single or multiple statements)
function exec(sql) {
  getDb().exec(sql);
}

// Helpers for prepared statements with positional parameters
function prepareAndBind(sql, params = []) {
  const database = getDb();
  const stmt = database.prepare(sql);
  try {
    stmt.bind(params);
    return stmt;
  } catch (err) {
    try { stmt.free(); } catch (_) {}
    throw err;
  }
}

// Run a statement that does not need to return rows (INSERT/UPDATE/DELETE)
function run(sql, params = []) {
  const stmt = prepareAndBind(sql, params);
  try {
    // step once for statements that do not produce result sets
    stmt.step();
  } finally {
    stmt.free();
  }
}

// Return all rows as array of objects
function all(sql, params = []) {
  const stmt = prepareAndBind(sql, params);
  try {
    const rows = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      rows.push(row);
    }
    return rows;
  } finally {
    stmt.free();
  }
}

// Return first row or null
function getOne(sql, params = []) {
  const stmt = prepareAndBind(sql, params);
  try {
    if (stmt.step()) {
      const row = stmt.getAsObject();
      return row;
    }
    return null;
  } finally {
    stmt.free();
  }
}

// Simple transaction helper (saves DB on success)
function transact(fn) {
  const database = getDb();
  database.exec('BEGIN');
  try {
    const result = fn();
    database.exec('COMMIT');
    saveDb();
    return result;
  } catch (err) {
    try { database.exec('ROLLBACK'); } catch (_) {}
    throw err;
  }
}

// Time helpers (UTC)
function nowUtc() {
  return new Date();
}

function toUtcDateStr(d = new Date()) {
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

module.exports = {
  initDb,
  getDb,
  saveDb,
  exec,
  run,
  all,
  getOne,
  transact,
  nowUtc,
  toUtcDateStr,
  DB_PATH,
  DATA_DIR
};