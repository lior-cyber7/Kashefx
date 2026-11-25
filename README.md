# كشف × حصانة — Kashf × AcadShield AI

Arabic-first, evidence-based cybersecurity & academic integrity platform powered by a **single FastAPI + Python backend** (`backend/*.py`) with SQLite persistence and a frozen React + TypeScript + Tailwind CSS frontend (`src/`).

---

## 1. Project Overview

**Kashf × AcadShield AI** unifies consumer phishing defense, technical URL forensics, isolated link detonation, data-leak prevention (DLP), academic writing integrity checks, and tamper-evident certificate verification inside one bilingual (Arabic RTL / English LTR) web application.

Instead of acting as a black-box verdict generator, every analyzer returns structured, source-attributed findings (`evidence_bundle`), explicit limitations (what was and was not checked), and defanged/masked outputs for safe inspection.

## 2. Purpose & Problems Addressed

1. **Regional & Bilingual Phishing Evasion**: Global scanners often miss Iraqi dialect wallet/telecom scams (ZainCash, Rafidain, Qi Card, delivery fees), zero-width/tatweel obfuscation, and WhatsApp hijacking lures.
2. **Unsafe Link Inspection**: Users frequently click shortened links, subdomain tricks (`paypal.com.verify-iq.info`), IDN homographs (`xn--`), or open redirects without knowing where they lead.
3. **Sensitive Data & Secret Leaks**: Students, researchers, and developers accidentally paste `.env` credentials, API tokens, private keys, phone numbers, or payment cards into public forms.
4. **Academic Integrity & Honest Probabilistic Reporting**: Conventional AI detectors often output overconfident binary claims on short or edited text. AcadShield pairs probabilistic stylometry (returning `Inconclusive` on short `< 35`-word or borderline text) with local 4-gram overlap, typing-cadence biometrics, and SHA-256 hash-chained certificates.
5. **Runtime Security Controls**: Built-in SSRF protection with IP pinning, sliding-window SQLite rate limiting, RBAC Developer Console, and 128 KB request body enforcement.

## 3. Main Features

| Feature Area | Description | Backend Route(s) |
| --- | --- | --- |
| **Message Phishing Scanner** | Context-aware Arabic (Iraqi/MSA) & English scam scoring, suspicious sentence extraction, URL extraction, bilingual family warning formatter | `POST /api/analyze` |
| **Batch & WhatsApp Scanner** | Parses up to 25 blank-line/WhatsApp-prefixed messages in Python and ranks them by risk score | `POST /api/analyze-batch` |
| **URL Lab & Live Inspector** | Static URL forensics + SSRF-safe DNS, Cloudflare DoH (`A`/`MX`/`TXT`/SPF), RDAP domain age, TLS inspection, redirect tracing, and Threat Intel sources | `POST /api/inspect-url` |
| **Isolated Safe URL Sandbox** | Non-executing Python HTTP/HTML inspector detecting credential forms, hidden iframes, obfuscated JS, meta-refresh, Telegram/Discord webhooks, and binary downloads | `POST /api/sandbox-url` |
| **Academic Shield** | Calibrated stylometric AI-vs-Human classifier (AR/EN), 4-gram shingling plagiarism overlap, and server-computed keystroke cadence biometrics | `POST /api/academic/analyze` |
| **Hash-Chained Certificates & Dashboard** | Issues SHA-256 hash-chained originality certificates and verifies chain integrity | `POST /api/certificates/issue`, `GET /api/certificates/verify`, `GET /api/dashboard` |
| **DLP & Secret Scanner** | Detects & redacts PEM private keys, API tokens, `.env` assignments, Bearer/JWT tokens, Iraqi phones, emails, and Luhn-validated payment cards | `POST /api/dlp/scan` |
| **20-Scenario Phishing IQ Lab** | Interactive bilingual phishing quiz backed dynamically by the Python analyzer | `GET /api/quiz`, `POST /api/quiz/verify` |
| **Community Trending** | Anonymous SHA-256 fingerprint reporting (24-hour deduplication) & 7-day trend aggregation | `POST /api/report`, `GET /api/trending` |
| **Developer Console & RBAC** | PBKDF2-HMAC-SHA256 auth, HMAC-SHA256 Bearer tokens, single-use invites, runtime thresholds, custom allowlist/blocklist domain rules, and audit logs | `/api/dev/*`, `GET /api/public-config` |
| **Model Evaluation & SaaS/Sandbox APIs** | Out-of-sample confusion-matrix/Brier evaluation, multi-engine stress benchmark, and Iraqi university SaaS ROI registry APIs | `GET /api/evaluation`, `/api/sandbox/*`, `/api/saas/tenants*` |

## 4. Final Technology Stack

- **Application Server & API Framework**: Python 3.11+ with **FastAPI** and **Uvicorn** (`backend/main.py`)
- **Database**: **SQLite** in WAL mode with `BEGIN IMMEDIATE` write locking (`backend/db.py`)
- **Frontend UI**: **React 19**, **TypeScript**, **Tailwind CSS v4**, **Vite 8** (`src/`)
- **Networking, Crypto & Parsing (Python stdlib)**: `urllib`, `http.client`, `socket`, `ssl`, `ipaddress`, `hashlib`, `hmac`, `secrets`, `html.parser`, `sqlite3`, `concurrent.futures`

## 5. Final Architecture

FastAPI (`backend/main.py`) is the **single application server** in production, serving all `/api/*` endpoints directly in-process via Python modules and serving the compiled React SPA (`dist/`). During local development, Vite runs separately as a hot-reloading dev proxy forwarding `/api/*` to FastAPI on port `8000`. Legacy Express (`server.ts`) and subprocess IPC (`bridge.py`) layers have been completely removed.

### Architecture Diagram

```text
+-------------------------------------------------------------------+
|                        Browser (React 19 SPA)                     |
|   Bilingual RTL/LTR UI · Canvas/Animations · Live Typing UI Bar   |
+---------------------------------+---------------------------------+
                                  |
            HTTPS / HTTP fetch('/api/...')
            [Dev: Vite :5173 proxies /api -> :8000]
            [Prod: FastAPI :8000 serves both API + dist/ SPA]
                                  v
+-------------------------------------------------------------------+
|                 FastAPI Single Server (backend/main.py)           |
|  Security Headers · 128 KB Body Cap · SQLite Rate Limit (30/60s)  |
+--------+---------------+---------------+---------------+----------+
         |               |               |               |
         v               v               v               v
+--------------+ +---------------+ +-------------+ +----------------+
| analyzer.py  | | url_inspector | | academic_   | | dev_console.py |
| rules_config | | url_sandbox   | | analyzer.py | | blockchain.py  |
| brands.py    | | threat_intel  | | ai_detector | | saas_sandbox   |
+------+-------+ +-------+-------+ +------+------+ +-------+--------+
       |                 |                |                |
       |                 v                |                |
       |      [External OSINT / Optional] |                |
       |      DNS · RDAP · TLS · VT/GSB/    |                |
       |      OpenPhish                   |                |
       |                                  |                |
       +-----------------+----------------+----------------+
                         |
                         v
+-------------------------------------------------------------------+
|               SQLite Database (backend/kashf.db, WAL)             |
|  reports · rate_limits · ledger_blocks · sandbox_runs ·           |
|  saas_tenants · dev_users · dev_invites · dev_settings ·          |
|  dev_domain_rules · dev_audit_log · dev_secrets                   |
+-------------------------------------------------------------------+
```

## 6. Division of Responsibilities

### What Python Handles (`backend/*.py`)
- All phishing/scam scoring, Arabic normalization (`text_utils.py`), batch/WhatsApp parsing (`parse_batch_messages`), and bilingual family warning generation (`build_family_warning_text`).
- All URL static forensics, homograph/Punycode analysis, SSRF/IP-pinned HTTP requests, TLS/RDAP/DoH lookups, Threat Intelligence aggregation, and non-executing HTML payload sandboxing.
- All academic AI stylometry, 4-gram plagiarism checks, authoritative typing cadence statistics (`compute_interval_stats`), DLP secret scanning/masking, and SHA-256 certificate ledger hashing.
- All authentication (PBKDF2 + HMAC), RBAC authorization, persistent rate limiting, SQLite reads/writes, stress benchmarks, SaaS economics, and HTTP routing + static `dist/` SPA delivery.

### What React / TypeScript Handles (`src/`)
- Bilingual (Arabic/English) UI rendering, RTL/LTR switching, accessibility, and responsive Tailwind layout.
- Visual animations & `<canvas>` rendering: share-card PNG image export (`src/utils/shareCard.ts`) and animated robot frame scrubbing (`src/utils/videoScrub.ts`).
- Instant non-blocking UI feedback: keystroke length clamping & URL chip highlighting (`src/utils/urlDetect.ts`), live typing preview (`src/utils/behaviorTracker.ts` on keydown without spamming HTTP endpoints), local browser history (`localStorage`), and state management for forms/tabs.

## 7. SQLite and Its Role (`backend/db.py` & Modules)

SQLite (`backend/kashf.db`, configurable via `KASHF_DB_PATH`) runs with `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`, and `PRAGMA foreign_keys=ON`. Write-critical paths use `db_transaction()` (`BEGIN IMMEDIATE`) to prevent race conditions.

- `reports` & `rate_limits`: Anonymous 24h-deduplicated scam report trending and persistent 60-second sliding-window API rate limits (`30` requests/IP).
- `ledger_blocks`: Append-only SHA-256 hash chain storing research originality certificates (`cert_id`, `doc_hash`, `prev_hash`, `block_hash`).
- `sandbox_runs` & `saas_tenants`: Stored multi-engine stress benchmark runs and university SaaS tenant records.
- `dev_users`, `dev_invites`, `dev_settings`, `dev_domain_rules`, `dev_audit_log`, `dev_secrets`: Developer Console RBAC accounts, single-use invite hashes, dynamic thresholds/toggles, custom domain allowlists/blocklists, audit history, and CSPRNG HMAC signing key fallback.

## 8. Request Flow & Frontend-to-Python Communication

1. **Browser → FastAPI**: React components call `fetch('/api/<route>', ...)` using relative `/api/...` paths.
2. **Development vs Production**:
   - In **production**, FastAPI serves `dist/index.html` and `/assets/*` directly on port `8000` and handles `/api/*` on the same origin.
   - In **development**, Vite (`npm run dev` on port `5173`) proxies `/api/*` requests to `http://localhost:8000` via `vite.config.ts`.
3. **Middleware Pipeline**: FastAPI checks payload size (`<= 128 KB`), runs `check_rate_limit()` against SQLite on mutation/expensive endpoints, executes the target Python module directly in-process, attaches security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`), and returns JSON.

## 9. Installation & Setup on Windows

### Prerequisites
- **Python 3.11+** (verify with `python --version`)
- **Node.js 20+** and **npm** (required only for building/developing the React frontend)

### Step 1: Clone & Create Python Virtual Environment
```powershell
git clone https://github.com/lior-cyber7/acadshiled.git
cd acadshiled
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Python & Frontend Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
npm install
```

### Dependencies Summary
- **Python (`backend/requirements.txt`)**: `fastapi>=0.110.0`, `uvicorn>=0.29.0`, `pytest>=8.0.0`, `httpx>=0.27.0`
- **Node/Frontend (`package.json`)**: React 19, TypeScript, Vite 8, Tailwind CSS v4, Lucide icons, `tsx` (for running TypeScript unit tests)

### Step 3: Environment Variables (`.env`)
Copy `.env.example` to `.env` in the project root and populate any optional keys needed (`backend/env_loader.py` loads `.env` automatically on startup without external packages):

| Variable | Required | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Optional | Enables optional Gemini auxiliary semantic check when toggled on |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | Google Safe Browsing v4 live Threat Intelligence check (server-side only) |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal v3 live Threat Intelligence check (server-side only) |

## 10. Building & Starting the Application (Windows)

### Production Mode (Single FastAPI Server — Recommended)
1. Build the React frontend into `dist/`:
   ```powershell
   npm run build
   ```
2. Start FastAPI:
   ```powershell
   python backend\main.py
   ```
   (Alternatively: `uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000`)
3. Open `http://127.0.0.1:8000` in your browser.

### Development Mode (Vite HMR + FastAPI API)
- **Terminal 1 (FastAPI API on `:8000`)**:
  ```powershell
  .\.venv\Scripts\Activate.ps1
  uvicorn main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
  ```
- **Terminal 2 (Vite dev server on `:5173`)**:
  ```powershell
  npm run dev
  ```
- Open `http://localhost:5173`.

## 11. Testing Commands (Windows)

```powershell
# Python syntax check
python -m py_compile backend\*.py

# Python unit, stage & security tests
python -m unittest backend\test_phase2_cleanup.py backend\test_phase3_migration.py backend\test_security_audit.py backend\test_api_fastapi.py backend\test_stage5_evaluation.py
python backend\test_analyzer.py
python backend\test_stage1_evidence.py
python backend\test_stage2_url_intel.py
python backend\test_stage3_messages.py
python backend\test_stage4_ai_detector.py
python backend\test_stage6_dev_console.py

# Out-of-sample accuracy & Brier calibration benchmark
python backend\evaluate_models.py

# Frontend unit tests, TypeScript check & production build
npx tsx --test src/utils/*.test.ts
npm run lint
npm run build
```

## 12. Common Windows Troubleshooting

- **`503 Frontend build not found in dist/` when visiting `http://127.0.0.1:8000`**:
  Run `npm run build` from the project root before starting `python backend\main.py`.
- **`.\.venv\Scripts\Activate.ps1` blocked by PowerShell Execution Policy**:
  Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once in PowerShell, or invoke `.\.venv\Scripts\python.exe backend\main.py` directly.
- **`'python3' is not recognized`**:
  On Windows use `python` (or `py -3`), never `python3`.
- **`503 KASHF_DEV_BOOTSTRAP_KEY must be configured` during Developer Console setup**:
  Add `KASHF_DEV_BOOTSTRAP_KEY="your-secret-key"` to `.env` in the repository root and restart `python backend\main.py`.
- **`sqlite3.OperationalError: database is locked` or cleanup errors**:
  Ensure only one server process is modifying `backend/kashf.db` at a time and no external SQLite GUI holds an exclusive write lock on `-wal`/`-shm` files.
- **`429 Rate Limit Exceeded`**:
  Default limit is `30` requests per `60` seconds per client IP stored persistently in `rate_limits`; wait 60 seconds before retrying.
