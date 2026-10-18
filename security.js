/**
 * Yuvraj Kurmi Portfolio — Security Engine
 * Cryptographic privacy hashing, sliding-window rate limiting, input sanitization, and admin authentication.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// 1. Secret Key Management for Privacy Hashing & Admin Auth
const KEY_FILE = path.join(DATA_DIR, '.security_keys.json');
let securityKeys = { adminKey: '', hmacSecret: '' };

if (fs.existsSync(KEY_FILE)) {
  try {
    securityKeys = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  } catch (e) {}
}

if (!securityKeys.adminKey || !securityKeys.hmacSecret) {
  securityKeys = {
    adminKey: process.env.ADMIN_KEY || `yk_sec_${crypto.randomBytes(18).toString('hex')}`,
    hmacSecret: process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex')
  };
  fs.writeFileSync(KEY_FILE, JSON.stringify(securityKeys, null, 2), { mode: 0o600 });
}

export const ADMIN_KEY = securityKeys.adminKey;
const HMAC_SECRET = securityKeys.hmacSecret;

// 2. Cryptographic Privacy Hashing (Never store raw visitor IP)
export function hashIp(ip) {
  if (!ip) return 'unknown';
  return crypto.createHmac('sha256', HMAC_SECRET).update(String(ip)).digest('hex').slice(0, 16);
}

// 3. Input Sanitization & HTML Escaping
export function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .trim();
}

// 4. Email format validation
export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return email.length <= 120 && re.test(email);
}

// 5. Sliding-Window Rate Limiter
class SlidingRateLimiter {
  constructor(limit = 5, windowMs = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.records = new Map();

    // Auto-cleanup stale entries every 5 minutes
    setInterval(() => this.cleanup(), 300000);
  }

  isLimited(key) {
    const now = Date.now();
    const timestamps = (this.records.get(key) || []).filter(t => now - t < this.windowMs);
    
    if (timestamps.length >= this.limit) {
      this.records.set(key, timestamps);
      return true;
    }

    timestamps.push(now);
    this.records.set(key, timestamps);
    return false;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, timestamps] of this.records.entries()) {
      const valid = timestamps.filter(t => now - t < this.windowMs);
      if (valid.length === 0) {
        this.records.delete(key);
      } else {
        this.records.set(key, valid);
      }
    }
  }
}

export const contactRateLimiter = new SlidingRateLimiter(5, 60000); // Max 5 contact posts/minute
export const apiRateLimiter = new SlidingRateLimiter(120, 60000);   // Max 120 general requests/minute

// 6. Admin Authentication Verification
export function verifyAdmin(req) {
  const authHeader = req.headers['authorization'] || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return false;
  const token = match[1].trim();
  
  // Timing-safe buffer comparison to prevent timing attacks
  const tokenBuf = Buffer.from(token);
  const secretBuf = Buffer.from(ADMIN_KEY);

  if (tokenBuf.length !== secretBuf.length) return false;
  return crypto.timingSafeEqual(tokenBuf, secretBuf);
}

// 7. Security Headers (OWASP Level 3 Compliance)
export function getSecurityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'self'; font-src https://fonts.gstatic.com 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; connect-src 'self';",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}
