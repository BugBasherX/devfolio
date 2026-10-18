# Yuvraj Kurmi Portfolio — The Sentence

> *"I build local-first systems that tell the truth."*

An independent systems and AI engineer portfolio based in Kathmandu, Nepal.

The frontend is a single file: `index.html`. The whole site is a single sentence that leans and rewrites itself as you scroll across six sentences: **home**, **system**, **work**, **stack**, **notes**, and **contact**.

Underneath is a production-grade full-stack backend with an auto-detecting **Dual-Engine Database** (Neon Serverless PostgreSQL in cloud / Native SQLite locally) and a cryptographic security engine.

---

## 📐 Concept & Interaction

- **Scroll, Swipe, or Arrows**: Lean the sentence and transition to the next state. Unchanged words glide to their new place via FLIP animation.
- **Underlined Words**: Click or tap to expand deep-dive passages.
- **Arrows Inside Passages**: Click an arrow (e.g., `What I build with →`) to jump directly to that sentence.
- **Deep Links & Section Redirects**: URLs like `/#work` or `/work` go straight to that sentence.

---

## 📂 Project Structure

```text
portfolio/
├── index.html          # Frontend: complete single-sentence interactive app
├── server.js           # Production backend: HTTP routing, compression, REST API
├── db.js               # Dual-Engine Database: Neon Serverless PG + native SQLite
├── security.js         # Security Engine: HMAC-SHA256 privacy, rate limiter, auth
├── Dockerfile          # Production containerization (node:22-alpine)
├── package.json        # Dependencies & scripts
├── .env.example        # Environment variable templates
├── .gitignore          # Safeguards secrets, keys, and local SQLite databases
├── sitemap.xml         # SEO search engine sitemap
├── robots.txt          # Crawler instructions & admin endpoint protection
├── contact.html        # Fallback redirect -> index.html#contact
├── system.html         # Fallback redirect -> index.html#system
├── work.html           # Fallback redirect -> index.html#work
├── stack.html          # Fallback redirect -> index.html#stack
├── notes.html          # Fallback redirect -> index.html#notes
└── data/               # Local persistence (created at runtime, gitignored)
    ├── portfolio.db    # Native SQLite database (WAL mode)
    └── .security_keys  # Auto-generated secret keys
```

---

## ⚡ Quick Start

### 1. Run Full-Stack Server Locally
```bash
# Start backend server (starts on http://localhost:3000)
npm start
```
*Note: Uses native SQLite in `data/portfolio.db` automatically with zero external setup.*

### 2. Run in Development Mode
```bash
npm run dev
```

### 3. Run Offline / Static Only
Open `index.html` directly in any web browser, or:
```bash
npx serve .
```

---

## 🗄️ Database Architecture

The backend features an **Auto-Detecting Dual Database Layer** ([db.js](file:///c:/Users/yuvii/OneDrive/Desktop/portfolio/db.js)):

| Environment | Engine | Connection | Storage |
| :--- | :--- | :--- | :--- |
| **Local Development** | Native SQLite (`node:sqlite`) | Embedded WAL Mode | `data/portfolio.db` |
| **Cloud Production** | Neon Serverless PostgreSQL | `@neondatabase/serverless` | AWS Cloud Postgres |

### Connecting to Neon DB:
1. Create a free database at [neon.tech](https://neon.tech).
2. Set `DATABASE_URL` in your `.env` or deployment dashboard:
   ```env
   DATABASE_URL=postgresql://<user>:<password>@<ep-proj>.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
3. Restart the server. Schema migrations and tables are initialized automatically!

---

## 🛡️ Security System

- **Privacy IP Hashing**: Visitor IPs are hashed with HMAC-SHA256 before database storage. Raw IP addresses are never written to disk.
- **Sliding-Window Rate Limiting**: Max 5 submissions per minute on `POST /api/contact` to prevent spam and denial-of-service.
- **Input Sanitization**: HTML entity escaping and RFC 5322 email validation.
- **Payload Clamping**: Requests larger than 32KB are immediately rejected.
- **Timing-Safe Admin Auth**: Admin inspection endpoints use `crypto.timingSafeEqual` against a protected Bearer token.
- **OWASP Headers**: Pre-configured with strict CSP, HSTS, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN`.

---

## 🌐 API Reference

### Public Endpoints:
- `GET /` — Serves `index.html` with GZIP compression.
- `GET /api/status` or `GET /api/system` — Node telemetry, Kathmandu local time (`NPT GMT+5:45`), memory RSS, uptime, and database stats.
- `GET /api/sentence` — Canonical structured sentence token data (`S` array).
- `POST /api/contact` — Submits a project inquiry.
  ```bash
  curl -X POST http://localhost:3000/api/contact \
    -H "Content-Type: application/json" \
    -d '{"name":"Alex","email":"alex@example.com","message":"Let us collaborate on low-latency C runtimes."}'
  ```
- `GET /api/health` — Instant health check status.

### Admin Endpoints (Protected):
Requires `Authorization: Bearer <ADMIN_KEY>`. *(Admin key is output to server log on startup and saved in `data/.security_keys.json`)*:
- `GET /api/admin/inquiries` — List all inquiries stored in SQLite/Neon.
- `POST /api/admin/inquiries/:id/read` — Mark an inquiry as read.
- `GET /api/admin/security-logs` — Audit log of rate limit trips and unauthorized attempts.

---

## 🚀 Deployment Guide

### Option A: Render / Railway / Fly.io (Recommended)
1. Push this folder to a GitHub repository.
2. Link your repository in Render or Railway.
3. Build command: `npm install` | Start command: `npm start`.
4. *(Optional)* Add `DATABASE_URL` for Neon DB, or add a persistent disk volume mounted at `/app/data` to keep SQLite.

### Option B: Docker Container
```bash
docker build -t yuvraj-portfolio .
docker run -d -p 3000:3000 -v $(pwd)/data:/app/data --name portfolio yuvraj-portfolio
```

---

## ✏️ Editing Portfolio Content

To update sentences or project descriptions, edit the `S` array in [index.html](file:///c:/Users/yuvii/OneDrive/Desktop/portfolio/index.html) (near line 155):
- `s`: The sentence text. Use `[word:id]` to make an openable word.
- `x[id]`: The detailed passage that opens when that word is clicked.

---

## 📬 Contact & License

- **Engineer:** Yuvraj Kurmi
- **Direct Mail:** [info@yuvrajkurmi.com.np](mailto:info@yuvrajkurmi.com.np)
- **GitHub:** [@BugBasherX](https://github.com/BugBasherX)
- **License:** MIT
