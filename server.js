/**
 * Yuvraj Kurmi Portfolio — Production Backend Server
 * 
 * Powered by:
 * - Native Node.js HTTP (zero external web framework dependencies)
 * - Dual Database Engine: Neon Serverless Postgres (Cloud) / Native SQLite (Local WAL Mode)
 * - Cryptographic Security Engine (HMAC-SHA256 privacy hashing, sliding-window rate limit, timing-safe admin auth)
 * - OWASP Hardened Security Headers
 * - Native Gzip/Deflate Compression
 */

import http from 'http';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

import { DB } from './db.js';
import {
  ADMIN_KEY,
  hashIp,
  sanitize,
  isValidEmail,
  contactRateLimiter,
  apiRateLimiter,
  verifyAdmin,
  getSecurityHeaders
} from './security.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || '3000', 10);

// Sentence Content Data
const SENTENCE_DATA = [
  {
    h: "home",
    t: "Yuvraj Kurmi",
    s: "[I:i] [build:build] [local-first:local] [systems:systems] that tell the [truth:truth].",
    x: {
      i: "am a self-taught systems and AI engineer in Kathmandu, working independently. Available for contract work on AI systems, low-latency runtimes and local-first apps: info@yuvrajkurmi.com.np, GitHub, write to me",
      build: "end to end, on one desk: architecture, implementation and documentation, made to be inherited and not guessed at.",
      local: "so nothing waits on the network. A C17/23 core handles audio and scheduling, and a Python layer handles reasoning, memory and routing.",
      systems: "six so far: NULL, CIPHERWRAITH, SENTINEL-X, GHOSTPROTOCOL, VOIDLINK and KC Class BHW.",
      truth: "by naming things honestly. Every project says what it is and what it isn't, and the documentation ships with the code."
    }
  },
  {
    h: "system",
    t: "System — Yuvraj Kurmi",
    s: "[Local-first:local] [systems:systems] are a [voice:voice], a [core:core] and a [mind:mind].",
    x: {
      local: "means nothing waits on the network. The runtime never waits on the intelligence layer, and the intelligence layer never waits on external networks.",
      systems: "here means NULL: three layers, one process boundary each, so a failure stays inside its layer and gets logged.",
      voice: "the interface to the microphone and speaker",
      core: "a C17/23 runtime and watchdog that handles I/O, wake-word and speech, plus scheduling, memory management and IPC.",
      mind: "a Python intelligence layer for reasoning, memory and routing"
    }
  },
  {
    h: "work",
    t: "Work — Yuvraj Kurmi",
    s: "I built six [systems:systems] that tell the [truth:truth].",
    x: {
      systems: "six so far: NULL (local-first voice assistant, C17/23 core & Python brain), CIPHERWRAITH (credential vault in Python using Fernet), SENTINEL-X (ICMP network monitor), GHOSTPROTOCOL (OpenCV Haar Cascade face access), VOIDLINK (ephemeral WebSockets), and KC Class BHW (creator coaching platform).",
      truth: "is the line inside every name above: what each project is, and what it isn't."
    }
  },
  {
    h: "stack",
    t: "Stack — Yuvraj Kurmi",
    s: "I work across [systems:systems], [AI:ai], [backend:backend], [frontend:frontend] and [security:security].",
    x: {
      systems: "C17/23 runtimes, watchdogs, IPC and process isolation.",
      ai: "local-first pipelines for speech, reasoning and memory, in Python.",
      backend: "Node.js, Express, SQLite, Flask and WebSockets.",
      frontend: "plain HTML, CSS and JavaScript, built to load fast.",
      security: "encryption with Fernet (AES-128), access control with OpenCV face detection, and network monitoring over ICMP."
    }
  },
  {
    h: "notes",
    t: "Notes — Yuvraj Kurmi",
    s: "I write the [documentation:docs] alongside the code, so nobody is left [guessing:guess].",
    x: {
      docs: "so the write-up ships with the project. Engineering notes are published transparently.",
      guess: "at how a system works. Everything here is built to be inherited, not guessed at."
    }
  },
  {
    h: "contact",
    t: "Contact — Yuvraj Kurmi",
    s: "Tell [me:me] what you are [building:bld].",
    x: {
      me: "Yuvraj Kurmi, an independent systems and AI engineer in Kathmandu: info@yuvrajkurmi.com.np, GitHub.",
      bld: "and who it is for. Contract work on AI systems, low-latency runtimes and local-first apps."
    }
  }
];

// Clean redirect mapping for old URLs & section routes
const ROUTE_REDIRECTS = {
  '/home': '/#home',
  '/system': '/#system',
  '/work': '/#work',
  '/stack': '/#stack',
  '/notes': '/#notes',
  '/contact': '/#contact',
  '/system.html': '/#system',
  '/work.html': '/#work',
  '/stack.html': '/#stack',
  '/notes.html': '/#notes',
  '/contact.html': '/#contact'
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8'
};

// Response helper with security headers & compression
function sendResponse(req, res, statusCode, headers, body, startTime) {
  const securityHeaders = getSecurityHeaders();
  const mergedHeaders = { ...securityHeaders, ...headers };

  // Log telemetry asynchronously
  if (startTime) {
    const duration = performance.now() - startTime;
    DB.logTelemetry(new URL(req.url, 'http://localhost').pathname, req.method, statusCode, duration);
  }

  const acceptEncoding = req.headers['accept-encoding'] || '';
  const isCompressible = /text|json|javascript|xml|svg/.test(mergedHeaders['Content-Type'] || '');

  if (isCompressible && body && body.length > 256) {
    if (/\bgzip\b/.test(acceptEncoding)) {
      mergedHeaders['Content-Encoding'] = 'gzip';
      delete mergedHeaders['Content-Length'];
      res.writeHead(statusCode, mergedHeaders);
      zlib.gzip(body, (err, compressed) => {
        if (!err) res.end(compressed);
        else res.end(body);
      });
      return;
    } else if (/\bdeflate\b/.test(acceptEncoding)) {
      mergedHeaders['Content-Encoding'] = 'deflate';
      delete mergedHeaders['Content-Length'];
      res.writeHead(statusCode, mergedHeaders);
      zlib.deflate(body, (err, compressed) => {
        if (!err) res.end(compressed);
        else res.end(body);
      });
      return;
    }
  }

  res.writeHead(statusCode, mergedHeaders);
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const startTime = performance.now();
  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const ipHash = hashIp(rawIp);

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };

  if (method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  // 1. Global Rate Limiter
  if (apiRateLimiter.isLimited(ipHash)) {
    DB.logSecurityEvent('API_RATE_LIMIT', ipHash, `Path: ${pathname}`);
    sendResponse(req, res, 429, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify({ error: "Rate limit exceeded. Please back off." }), startTime);
    return;
  }

  // 2. Clean Route Redirects
  if (ROUTE_REDIRECTS[pathname]) {
    res.writeHead(302, { 'Location': ROUTE_REDIRECTS[pathname] });
    res.end();
    return;
  }

  // 3. Health Check
  if (pathname === '/api/health' && method === 'GET') {
    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify({ status: "healthy", database: DB.getEngineType(), timestamp: new Date().toISOString() }), startTime);
    return;
  }

  // 4. Node Telemetry & Status
  if ((pathname === '/api/status' || pathname === '/api/system') && method === 'GET') {
    const uptime = Math.floor(process.uptime());
    const mem = process.memoryUsage();
    
    const now = new Date();
    const ktmTime = new Date(now.getTime() + (now.getTimezoneOffset() * 60000) + (345 * 60000));
    const stats = await DB.getInquiryStats();

    const payload = {
      engineer: "Yuvraj Kurmi",
      mission: "I build local-first systems that tell the truth.",
      location: "Kathmandu, Nepal (GMT+5:45)",
      localTimeNPT: ktmTime.toTimeString().split(' ')[0] + " NPT",
      uptimeSeconds: uptime,
      memoryRSS: `${(mem.rss / 1024 / 1024).toFixed(2)} MB`,
      heapUsed: `${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      database: DB.getEngineType(),
      databaseStats: {
        totalInquiries: stats.total || 0,
        unreadInquiries: stats.unread || 0
      },
      systemsCount: 6,
      systems: ["NULL", "CIPHERWRAITH", "SENTINEL-X", "GHOSTPROTOCOL", "VOIDLINK", "KC Class BHW"]
    };

    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify(payload, null, 2), startTime);
    return;
  }

  // 5. Sentence Content
  if (pathname === '/api/sentence' && method === 'GET') {
    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600'
    }, JSON.stringify(SENTENCE_DATA, null, 2), startTime);
    return;
  }

  // 6. Contact Submission
  if (pathname === '/api/contact' && method === 'POST') {
    if (contactRateLimiter.isLimited(ipHash)) {
      DB.logSecurityEvent('CONTACT_SPAM_BLOCK', ipHash, 'Exceeded 5 messages/minute threshold');
      sendResponse(req, res, 429, {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }, JSON.stringify({ error: "Too many messages sent. Please wait before submitting again." }), startTime);
      return;
    }

    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 32768) {
        DB.logSecurityEvent('PAYLOAD_SIZE_VIOLATION', ipHash, `Size: ${body.length} bytes`);
        res.destroy();
      }
    });

    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const name = sanitize(payload.name || 'Anonymous');
        const email = String(payload.email || '').trim().toLowerCase();
        const message = sanitize(payload.message || '');

        if (!isValidEmail(email)) {
          sendResponse(req, res, 400, {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }, JSON.stringify({ error: "A valid email address is required." }), startTime);
          return;
        }

        if (!message || message.length < 5) {
          sendResponse(req, res, 400, {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }, JSON.stringify({ error: "Message must contain at least 5 characters." }), startTime);
          return;
        }

        const inquiryId = `inq_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
        await DB.saveInquiry({
          id: inquiryId,
          name,
          email,
          message,
          ipHash
        });

        sendResponse(req, res, 201, {
          ...corsHeaders,
          'Content-Type': 'application/json'
        }, JSON.stringify({
          success: true,
          inquiryId,
          database: DB.getEngineType(),
          message: `Inquiry recorded in ${DB.getEngineType()}. Thank you, ${name}.`
        }), startTime);
      } catch (err) {
        DB.logSecurityEvent('MALFORMED_JSON_ATTEMPT', ipHash, err.message);
        sendResponse(req, res, 400, {
          ...corsHeaders,
          'Content-Type': 'application/json'
        }, JSON.stringify({ error: "Malformed JSON payload." }), startTime);
      }
    });
    return;
  }

  // 7. Admin Endpoints
  if (pathname === '/api/admin/inquiries' && method === 'GET') {
    if (!verifyAdmin(req)) {
      DB.logSecurityEvent('UNAUTHORIZED_ADMIN_READ', ipHash);
      sendResponse(req, res, 401, {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }, JSON.stringify({ error: "Unauthorized. Provide valid Bearer token." }), startTime);
      return;
    }

    const inquiries = await DB.getInquiries(100);
    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify({ database: DB.getEngineType(), inquiries, count: inquiries.length }, null, 2), startTime);
    return;
  }

  if (pathname.startsWith('/api/admin/inquiries/') && pathname.endsWith('/read') && method === 'POST') {
    if (!verifyAdmin(req)) {
      DB.logSecurityEvent('UNAUTHORIZED_ADMIN_WRITE', ipHash);
      sendResponse(req, res, 401, {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }, JSON.stringify({ error: "Unauthorized." }), startTime);
      return;
    }

    const id = pathname.split('/')[4];
    await DB.markAsRead(id);
    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify({ success: true, markedRead: id }), startTime);
    return;
  }

  if (pathname === '/api/admin/security-logs' && method === 'GET') {
    if (!verifyAdmin(req)) {
      DB.logSecurityEvent('UNAUTHORIZED_ADMIN_AUDIT', ipHash);
      sendResponse(req, res, 401, {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }, JSON.stringify({ error: "Unauthorized." }), startTime);
      return;
    }

    const logs = await DB.getSecurityLogs(100);
    sendResponse(req, res, 200, {
      ...corsHeaders,
      'Content-Type': 'application/json'
    }, JSON.stringify({ database: DB.getEngineType(), logs, count: logs.length }, null, 2), startTime);
    return;
  }

  // 8. Static File Serving
  let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);

  if (!filePath.startsWith(__dirname)) {
    DB.logSecurityEvent('DIR_TRAVERSAL_ATTEMPT', ipHash, `Target: ${pathname}`);
    sendResponse(req, res, 403, { 'Content-Type': 'text/plain' }, 'Access Denied', startTime);
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      if (!path.extname(filePath)) {
        filePath += '.html';
      }
    }

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        fs.readFile(path.join(__dirname, 'index.html'), (idxErr, idxContent) => {
          if (idxErr) {
            sendResponse(req, res, 404, { 'Content-Type': 'text/plain' }, '404 Not Found', startTime);
          } else {
            sendResponse(req, res, 200, {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'no-cache'
            }, idxContent, startTime);
          }
        });
        return;
      }

      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      const isHtml = ext === '.html';

      sendResponse(req, res, 200, {
        'Content-Type': contentType,
        'Cache-Control': isHtml ? 'no-cache' : 'public, max-age=86400, stale-while-revalidate=604800'
      }, content, startTime);
    });
  });
});

server.listen(PORT, () => {
  console.log(`[Yuvraj Kurmi Portfolio] Live at http://localhost:${PORT}`);
  console.log(`- Active Database: ${DB.getEngineType()}`);
  console.log(`- Security: HMAC-SHA256 privacy hashing, sliding-window rate limit, OWASP headers`);
  console.log(`- Admin Key: ${ADMIN_KEY}`);
});

// Process signal handlers
process.on('SIGINT', () => {
  console.log('Shutting down server gracefully...');
  server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('Shutting down server gracefully...');
  server.close(() => process.exit(0));
});
