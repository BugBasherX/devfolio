/**
 * Yuvraj Kurmi Portfolio — Dual Database Engine
 * Auto-detects between Neon Serverless Postgres (Production/Cloud) and Native SQLite (Local/Offline).
 */

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read .env if present (lightweight parser without external dotenv dependency)
const ENV_PATH = path.join(__dirname, '.env');
if (fs.existsSync(ENV_PATH)) {
  const envContent = fs.readFileSync(ENV_PATH, 'utf8');
  envContent.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const [k, ...v] = trimmed.split('=');
    if (k && v.length) {
      const val = v.join('=').trim().replace(/^["']|["']$/g, '');
      if (!process.env[k.trim()]) process.env[k.trim()] = val;
    }
  });
}

const DATABASE_URL = process.env.DATABASE_URL || process.env.NEON_DATABASE_URL;

let isNeon = false;
let sqlClient = null;
let sqliteDb = null;

// Statements for SQLite fallback
let insertInquiryStmt, listInquiriesStmt, countInquiriesStmt, markInquiryReadStmt;
let insertSecurityAuditStmt, listSecurityAuditStmt, insertTelemetryStmt;

if (DATABASE_URL && DATABASE_URL.startsWith('postgres')) {
  try {
    const { neon } = await import('@neondatabase/serverless');
    sqlClient = neon(DATABASE_URL);
    isNeon = true;
    console.log('[DB] Connecting to Neon Serverless Postgres...');

    // Initialize Neon Postgres Schema
    await sqlClient`
      CREATE TABLE IF NOT EXISTS inquiries (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(160) NOT NULL,
        message TEXT NOT NULL,
        ip_hash VARCHAR(64) NOT NULL,
        status VARCHAR(20) DEFAULT 'unread',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;

    await sqlClient`
      CREATE TABLE IF NOT EXISTS security_audit (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(64) NOT NULL,
        ip_hash VARCHAR(64) NOT NULL,
        details TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;

    await sqlClient`
      CREATE TABLE IF NOT EXISTS telemetry (
        id SERIAL PRIMARY KEY,
        endpoint VARCHAR(120) NOT NULL,
        method VARCHAR(10) NOT NULL,
        status_code INT NOT NULL,
        response_time_ms REAL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    console.log('[DB] Connected to Neon Serverless PostgreSQL successfully.');
  } catch (err) {
    console.warn('[DB] Failed to initialize Neon Postgres, falling back to SQLite:', err.message);
    isNeon = false;
  }
}

if (!isNeon) {
  const { DatabaseSync } = await import('node:sqlite');
  const DATA_DIR = path.join(__dirname, 'data');
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const DB_PATH = path.join(DATA_DIR, 'portfolio.db');
  sqliteDb = new DatabaseSync(DB_PATH);

  // Enable WAL Mode
  sqliteDb.exec('PRAGMA journal_mode = WAL;');
  sqliteDb.exec('PRAGMA foreign_keys = ON;');

  // Initialize SQLite Schema
  sqliteDb.exec(`
    CREATE TABLE IF NOT EXISTS inquiries (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      ip_hash TEXT NOT NULL,
      status TEXT DEFAULT 'unread',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS security_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      ip_hash TEXT NOT NULL,
      details TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS telemetry (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      response_time_ms REAL,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  insertInquiryStmt = sqliteDb.prepare(`
    INSERT INTO inquiries (id, name, email, message, ip_hash, status)
    VALUES (?, ?, ?, ?, ?, 'unread')
  `);

  listInquiriesStmt = sqliteDb.prepare(`
    SELECT id, name, email, message, ip_hash, status, created_at
    FROM inquiries
    ORDER BY created_at DESC
    LIMIT ?
  `);

  countInquiriesStmt = sqliteDb.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN status = 'unread' THEN 1 ELSE 0 END) as unread
    FROM inquiries
  `);

  markInquiryReadStmt = sqliteDb.prepare(`
    UPDATE inquiries SET status = 'read' WHERE id = ?
  `);

  insertSecurityAuditStmt = sqliteDb.prepare(`
    INSERT INTO security_audit (event_type, ip_hash, details)
    VALUES (?, ?, ?)
  `);

  listSecurityAuditStmt = sqliteDb.prepare(`
    SELECT id, event_type, ip_hash, details, created_at
    FROM security_audit
    ORDER BY created_at DESC
    LIMIT ?
  `);

  insertTelemetryStmt = sqliteDb.prepare(`
    INSERT INTO telemetry (endpoint, method, status_code, response_time_ms)
    VALUES (?, ?, ?, ?)
  `);

  console.log('[DB] Using local SQLite database (data/portfolio.db)');
}

export const DB = {
  getEngineType() {
    return isNeon ? 'Neon Serverless PostgreSQL' : 'Native SQLite (WAL Mode)';
  },

  async saveInquiry({ id, name, email, message, ipHash }) {
    if (isNeon) {
      await sqlClient`
        INSERT INTO inquiries (id, name, email, message, ip_hash, status)
        VALUES (${id}, ${name}, ${email}, ${message}, ${ipHash}, 'unread')
      `;
      return { id, name, email, status: 'unread' };
    } else {
      insertInquiryStmt.run(id, name, email, message, ipHash);
      return { id, name, email, status: 'unread' };
    }
  },

  async getInquiries(limit = 50) {
    if (isNeon) {
      const rows = await sqlClient`
        SELECT id, name, email, message, ip_hash, status, created_at
        FROM inquiries
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;
      return rows;
    } else {
      return listInquiriesStmt.all(limit);
    }
  },

  async getInquiryStats() {
    if (isNeon) {
      const rows = await sqlClient`
        SELECT 
          COUNT(*)::int as total,
          COUNT(CASE WHEN status = 'unread' THEN 1 END)::int as unread
        FROM inquiries
      `;
      return rows[0] || { total: 0, unread: 0 };
    } else {
      const res = countInquiriesStmt.get();
      return {
        total: res.total || 0,
        unread: res.unread || 0
      };
    }
  },

  async markAsRead(id) {
    if (isNeon) {
      await sqlClient`
        UPDATE inquiries SET status = 'read' WHERE id = ${id}
      `;
    } else {
      markInquiryReadStmt.run(id);
    }
    return { success: true, id };
  },

  async logSecurityEvent(eventType, ipHash, details = '') {
    try {
      if (isNeon) {
        await sqlClient`
          INSERT INTO security_audit (event_type, ip_hash, details)
          VALUES (${eventType}, ${ipHash}, ${details})
        `;
      } else {
        insertSecurityAuditStmt.run(eventType, ipHash, details);
      }
    } catch (e) {}
  },

  async getSecurityLogs(limit = 50) {
    if (isNeon) {
      const rows = await sqlClient`
        SELECT id, event_type, ip_hash, details, created_at
        FROM security_audit
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;
      return rows;
    } else {
      return listSecurityAuditStmt.all(limit);
    }
  },

  async logTelemetry(endpoint, method, statusCode, responseTimeMs) {
    try {
      if (isNeon) {
        await sqlClient`
          INSERT INTO telemetry (endpoint, method, status_code, response_time_ms)
          VALUES (${endpoint}, ${method}, ${statusCode}, ${responseTimeMs})
        `;
      } else {
        insertTelemetryStmt.run(endpoint, method, statusCode, responseTimeMs);
      }
    } catch (e) {}
  }
};
