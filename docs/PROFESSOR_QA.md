# Kashf × AcadShield AI — Professor Defense & Study Guide

This guide explains the real architecture, Python modules, implemented algorithms, security controls, and request flows in the **Kashf × AcadShield AI** repository so you can present and defend every part of the system accurately.

---

## Section A — Project Overview

### What Kashf × AcadShield AI Does
**Kashf × AcadShield AI** is a bilingual (Arabic RTL & English LTR) cybersecurity and academic integrity web platform. It helps students, families, faculty, and developers detect phishing messages, inspect suspicious URLs safely, scan text for leaked secrets/PII, evaluate academic originality, and issue tamper-evident verification certificates.

### Why It Was Developed & Problems Addressed
1. **Arabic & Iraqi Phishing Gaps**: Many generic phishing filters miss Arabic/Iraqi dialect scams (such as fake ZainCash, Rafidain Bank, Qi Card, or parcel-customs messages) and filter-evasion tricks like invisible Unicode zero-width characters or letter elongation (tatweel).
2. **Risk of Clicking Unknown Links**: Users need a safe way to see what a URL is doing—brand impersonation, IDN homographs, open redirects, hidden iframes, or Telegram exfiltration scripts—without executing malicious JavaScript in their own browser.
3. **Accidental Secret Exposure (DLP)**: Developers and students often paste API keys, `.env` passwords, JWTs, or private keys into chat or forms.
4. **Honest Academic Integrity Screening**: Many commercial AI detectors claim 100% certainty on short or edited essays. AcadShield combines probabilistic stylometry (explicitly returning `Inconclusive` on short or mixed text), 4-word shingling plagiarism checks, typing biometrics, and SHA-256 chained certificates.

### Main Features
- **Single & Batch/WhatsApp Scam Scanner** (`POST /api/analyze`, `POST /api/analyze-batch`)
- **URL Forensics Lab & Live Probe** (`POST /api/inspect-url`)
- **Isolated Static URL Sandbox** (`POST /api/sandbox-url`)
- **Academic Shield (AI Stylometry + 4-Gram Plagiarism + Typing Biometrics)** (`POST /api/academic/analyze`)
- **DLP Secret & PII Scanner** (`POST /api/dlp/scan`)
- **Tamper-Evident SHA-256 Certificate Hash Chain & Dashboard** (`POST /api/certificates/issue`, `GET /api/certificates/verify`, `GET /api/dashboard`)
- **20-Scenario Phishing IQ Lab** (`GET /api/quiz`, `POST /api/quiz/verify`)
- **Anonymous Community Scam Trends** (`POST /api/report`, `GET /api/trending`)
- **Developer Console (RBAC, Runtime Settings, Domain Rules, Invites, Audit Log)** (`/api/dev/*`)
- **Out-of-Sample Evaluation & University SaaS/Stress Benchmark APIs** (`GET /api/evaluation`, `/api/sandbox/*`, `/api/saas/tenants*`)

---

## Section B — Architecture

```text
+-------------------------------------------------------------------+
|               Browser: React 19 + TypeScript + Tailwind           |
|   Renders Arabic/English UI, Canvas animations, and forms         |
+---------------------------------+---------------------------------+
                                  |
                         HTTP fetch('/api/...')
                                  v
+-------------------------------------------------------------------+
|                 FastAPI Single Server (backend/main.py)           |
|   - Validates JSON payloads (Pydantic)                            |
|   - Enforces 128 KB body limit & security HTTP headers            |
|   - Checks SQLite persistent rate limit (30 requests / 60 sec)    |
|   - Serves compiled React static files from dist/                 |
+--------+----------------+-----------------+--------------+--------+
         |                |                 |              |
         v                v                 v              v
  analyzer.py     url_inspector.py   academic_       dev_console.py
  rules_config    url_sandbox.py     analyzer.py     blockchain.py
  brands.py       threat_intel.py    ai_detector.py  saas_sandbox.py
         |                |                 |              |
         +----------------+--------+--------+--------------+
                                   |
                                   v
                    SQLite (backend/kashf.db, WAL)
```

### Role of Each Layer
- **React (`src/`)**: Renders the bilingual user interface, manages client tabs/inputs, draws `<canvas>` visuals (`shareCard.ts`, `videoScrub.ts`), handles synchronous clipboard/JSON download clicks, and sends JSON requests to `/api/*`.
- **FastAPI (`backend/main.py`)**: Acts as the single HTTP server. It parses requests with Pydantic, applies security middleware, routes calls directly to Python functions in memory (no subprocess bridge), and serves the built React app from `dist/`.
- **Python Core (`backend/*.py`)**: Executes all detection logic, scoring, forensic URL checks, SSRF-safe network inspection, statistical AI detection, cryptography, and database operations.
- **SQLite (`backend/kashf.db`)**: Lightweight embedded relational database requiring no external DB daemon, configured in WAL mode (`PRAGMA journal_mode=WAL`) for safe concurrent reads and serialized `BEGIN IMMEDIATE` writes.

### Why Python Is the Main Backend & Why Some TypeScript Remains
- **Why Python**: Python provides clean readability for a university project, strong standard-library support (`ipaddress`, `ssl`, `http.client`, `hashlib`, `hmac`, `sqlite3`, `html.parser`, `unicodedata`), and unified maintenance—all security rules, forensics, and ML/statistical math stay in one backend language.
- **Why Some TypeScript Remains**: React UI components (`.tsx`), Tailwind styling, browser `<canvas>` rendering (`shareCard.ts`, `videoScrub.ts`), and per-keystroke UI helpers (`urlDetect.ts` for character clamping/URL chips/highlight JSX spans, and `behaviorTracker.ts` for live keystroke bar previews) must run locally inside the browser so typing does not trigger 30+ HTTP calls per second and hit the rate limiter. Authoritative calculation still runs in Python upon submission.

---

## Section C — Python Modules (`backend/`)

| File Name | Purpose & Why It Exists | Important Functions | Input | Output | Dependencies |
| --- | --- | --- | --- | --- | --- |
| `main.py` | Single FastAPI server entrypoint, middleware, API routing, and `dist/` SPA static serving. | `enforce_body_size_limit`, `add_security_headers`, `analyze`, `analyze_batch_endpoint`, `_serve_spa_or_asset` | HTTP requests & Pydantic JSON models | JSON responses, HTTP errors (`400`/`401`/`403`/`404`/`413`/`429`), static files | `fastapi`, `uvicorn`, `pydantic`, `env_loader`, all feature modules |
| `analyzer.py` | Context-aware Arabic/English scam engine, batch parser, and family warning generator. | `analyze_message`, `analyze_batch`, `parse_batch_messages`, `build_family_warning_text`, `extract_urls`, `compute_fingerprint` | Message `str` / batch `raw_text` or `list[str]` | Risk score (`0–100`), verdict, category, reasons, `family_warning`, `evidence_bundle` | `rules_config`, `text_utils`, `url_inspector`, `evidence_engine`, `dev_console` (lazy) |
| `rules_config.py` | Centralizes all scoring weights, thresholds, keyword lists, suspicious TLDs, homograph map, and AI discourse cues. | Data constants (`MESSAGE_RULE_POINTS`, `URL_FORENSIC_WEIGHTS`, phrase lists) | N/A | Read-only configuration dictionaries and sets | Stdlib only |
| `brands.py` | Registry of 27 global & Iraqi regional brands (PayPal, ZainCash, Rafidain Bank, Qi Card, etc.) and official domains. | `BRANDS` list | N/A | List of `BrandEntry` dicts | Stdlib (`typing`) |
| `text_utils.py` | Shared Arabic normalization, edit distance, and domain suffix matching without duplication. | `normalize_arabic_with_map`, `normalize_arabic`, `levenshtein_distance`, `matches_domain_suffix` | Raw Arabic/Latin `str` | Normalized `str` + original index map, `int` distance, `bool` | Stdlib (`re`) |
| `evidence_engine.py` | Standardized evidence, conflict detection, and honest calibrated/uncalibrated confidence assessment. | `make_evidence`, `make_limitation`, `compute_evidence_strength`, `build_evidence_bundle` | Lists of `EvidenceItem`, flags, optional calibrated prob | `EvidenceBundle` dict (`evidence`, `conflicts`, `limitations`, `confidence`) | Stdlib (`datetime`, `typing`) |
| `url_inspector.py` | Static URL forensics, homograph check, SSRF guard, IP-pinned HTTP redirect tracer, TLS check, and live probe. | `inspect_url_forensics`, `shannon_entropy`, `defang_url`, `_is_public_ip`, `_resolve_public_host`, `trace_safe_redirects`, `probe_url_live` | Raw URL `str` | `UrlForensics` or `LiveUrlProbeResult` dict | `brands`, `rules_config`, `text_utils`, `threat_intel`, `evidence_engine` |
| `url_sandbox.py` | Non-executing Python HTTP + HTML/DOM payload inspector (`128 KB` read cap). | `inspect_html_payload`, `detonate_url_in_sandbox` | Raw URL `str`, captured HTML `str` | Sandbox verdict, DOM telemetry, network trace, `what_it_tries_to_do`, `safety_guarantees` | `url_inspector` |
| `threat_intel.py` | Concurrent real OSINT clients (GSB v4, VirusTotal v3, OpenPhish cache) + RDAP & DoH. | `query_all_threat_intel`, `lookup_rdap_domain_age`, `lookup_dns_records` | Normalized URL & host `str` | List of `ThreatSourceResult` (`hit`/`clean`/`not_configured`/`unavailable`/`error`) | `evidence_engine` |
| `ai_detector.py` | Probabilistic Arabic & English AI-vs-Human stylometric analyzer with OOF Platt calibration. | `detect_text_language`, `extract_stylometric_features`, `_CalibratedLangModel`, `analyze_ai_vs_human` | Essay/text `str` | Classification (`human_leaning`/`ai_leaning`/`inconclusive`), probability, metrics, bundle | `ai_training_corpus`, `rules_config`, `text_utils`, `evidence_engine` |
| `ai_training_corpus.py` | Curated reference corpus (`TRAIN_AR`, `TRAIN_EN`, 32 passages each) strictly disjoint from `eval_datasets.py`. | `TRAIN_AR`, `TRAIN_EN` | N/A | Lists of `(text, label)` tuples | None |
| `academic_analyzer.py` | Combines AI stylometry, 4-word shingling plagiarism overlap, typing cadence stats, and DLP secret scanning. | `analyze_academic_text`, `scan_dlp_content`, `compute_interval_stats`, `build_behavior_telemetry`, `classify_behavior_preview` | Text `str`, optional reference `str`, optional behavior `dict` | Originality score, plagiarism matches, behavior summary, or redacted DLP findings | `ai_detector`, `analyzer`, `rules_config`, `text_utils` |
| `blockchain.py` | Tamper-evident SQLite SHA-256 certificate hash chain & executive dashboard metrics. | `issue_certificate`, `verify_certificate`, `verify_chain_integrity`, `get_dashboard_summary` | Certificate fields + text | Certificate block dict (`ACAD-0001-...`) or verification flags | `db` |
| `db.py` | SQLite WAL connection management, `BEGIN IMMEDIATE` transactions, persistent rate limiting, and trending reports. | `open_db`, `db_transaction`, `check_rate_limit`, `save_report`, `get_trending`, `get_community_stats` | Keys, categories, fingerprints, scores | Booleans, 7-day buckets, community stats | Stdlib (`sqlite3`, `contextlib`, `os`) |
| `dev_console.py` | Developer Console PBKDF2 authentication, HMAC Bearer tokens, RBAC, invites, runtime settings, custom domain rules, and audit logs. | `bootstrap_owner`, `login_developer`, `authenticate_token`, `create_invite`, `claim_invite`, `update_runtime_settings`, `upsert_domain_rule` | Credentials, tokens, role tuples, settings/domain updates | Session tokens, serialized users, audit logs, public config flags | `db`, `env_loader` |
| `quiz.py` | 20 bilingual phishing vs. legitimate training scenarios verified by `analyze_message`. | `get_quiz_scenarios`, `verify_quiz_answer` | Scenario ID, `is_scam` guess, language | Correctness, explanation, full analyzer proof | `analyzer` |
| `saas_sandbox.py` | Multi-engine university stress benchmark and Iraqi university SaaS ROI pricing & tenant registry. | `run_sandbox_benchmark`, `calculate_saas_economics`, `register_saas_tenant`, `list_saas_tenants`, `delete_saas_tenant` | Department, load size, student/faculty counts, tier | Benchmark latency/SLA stats, USD/IQD savings, tenant list | `academic_analyzer`, `analyzer`, `db` |
| `eval_datasets.py` & `evaluate_models.py` | Disjoint held-out evaluation datasets and out-of-sample confusion-matrix / Brier runner. | `compute_binary_metrics`, `run_all_evaluations` | Built-in held-out test cases | Accuracy, precision, recall, F1, FPR, Brier score | `ai_detector`, `analyzer`, `url_inspector` |
| `env_loader.py` | Zero-dependency `.env` parser invoked before reading env settings. | `load_project_env` | Optional `.env` path | Populates `os.environ` via `setdefault` | Stdlib (`os`, `pathlib`) |

---

## Section D — Actual Algorithms Implemented

1. **Arabic Normalization & Index Mapping (`text_utils.py`, `analyzer.py`)**:
   - Strips Arabic diacritics (tashkeel), tatweel elongation (`ـ`), and invisible zero-width chars (`\u200B-\u200D`, `\uFEFF`), and folds `أ/إ/آ → ا`, `ى → ي`, `ة → ه`.
   - Builds a parallel `index_map` linking each normalized character back to its index in the original string so exact un-normalized substrings can be highlighted in the UI.
2. **Context-Aware Scam Scoring & Dampeners (`analyzer.py`, `rules_config.py`)**:
   - Sums rule weights across URL forensics (up to `+55` custom blocklist, `+35` brand impersonation, `+25` IP/homograph/open redirect, etc.) and linguistic rules (`+35` OTP/credential request, `+35` OAuth consent trap, `+30` subtle BEC, `+25` wire/gift-card, `+20` coercive urgency, `+15` soft urgency only when paired with links/actions/sensitive requests).
   - **False-positive guards**: Ignores OTP triggers if the message is a `"do not share this code"` warning with no links/actions (`has_no_share_guard`); subtracts `-20` (`BENIGN_CONTEXT_DAMPENER`) for campus/meeting contexts without risky signals, and `-10` (`LOW_SIGNAL_DAMPENER`) if only weak hints appear. Clamps final score to `0–100` (`<30` Safe, `30–64` Suspicious, `>=65` Dangerous by default, adjustable in Developer Console).
3. **URL Forensics, Homograph & Brand Lookalike Detection (`url_inspector.py`)**:
   - Computes **Shannon entropy** $H = -\sum p_i \log_2(p_i)$ on the main domain label (`>= 3.7` triggers high-randomness flag on labels `>= 8` chars).
   - Decodes `xn--` Punycode using Python `idna` codec, inspects `unicodedata.name` per character to detect mixed Latin/Cyrillic/Greek scripts, and maps Cyrillic/Greek confusables (`CONFUSABLE_MAP`) to an ASCII skeleton.
   - Runs **Levenshtein edit distance** (`<= 1` for short aliases, `<= 2` for `>= 5`-char aliases) after normalizing leetspeak (`0→o`, `1→l`, `5→s`, `3→e`, `rn→m`) against 27 official brands.
   - Classifies URLs honestly into 4 states: `malicious`, `suspicious`, `no_known_threat` (only when Threat Intel returns clean or domain is verified official), or `unknown` (never calls an unseen domain "safe").
4. **AI-vs-Human Stylometry (`ai_detector.py`)**:
   - Not a neural LLM! Uses **10 deterministic numerical features**: sentence-length CV (`burstiness`), adjacent sentence delta ratio, `root_ttr`, `hapax_ratio`, bigram repetition, sentence-starter uniformity, AI discourse connector density, personal-voice cue rate, punctuation Shannon entropy, and `lm_log_ratio` ($H_{\text{human}} - H_{\text{ai}}$) computed from two Laplace-smoothed **character-3gram + word-2gram language models** (`0.55 * char_CE + 0.45 * word_CE`).
   - Trains an **L2-regularized logistic regression** classifier via gradient descent on `TRAIN_AR` / `TRAIN_EN` (32 passages each), using **leave-one-out out-of-fold logits** for **Platt probability calibration**.
   - **Scientific honesty gates**: Any text with `< 35` words (`MIN_AI_CALIBRATION_WORDS`), probability inside `[0.35, 0.65]`, or conflicting AI+human cues inside `[0.25, 0.78]` returns `inconclusive`.
5. **Plagiarism Overlap (`academic_analyzer.py`)**:
   - Tokenizes normalized text into overlapping **4-word shingles** (`_word_shingles`) and measures set intersection ratio (`overlap_pct`) and Jaccard similarity against any attached reference plus 3 built-in sample documents.
6. **Typing Behavioral Biometrics (`academic_analyzer.py`)**:
   - Filters inter-keystroke gaps to `[10, 2500] ms`, computes mean and population standard deviation (`compute_interval_stats`), calculates `paste_ratio`, and classifies sessions (`human_verified` if `keystrokes >= 15`, `paste_ratio < 0.25`, `interval_std_ms >= 20`; `robotic_cadence` if std `< 20`; `bulk_pasted` if `paste_ratio >= 0.65`; `mixed_input`; or `not_captured`).
7. **DLP Secret Detection & Luhn Validation (`academic_analyzer.py`)**:
   - Scans up to 20,000 chars with regexes for PEM private keys, OpenAI/GitHub/AWS/Slack/Stripe/Google/HuggingFace keys, `.env` credential assignments, Bearer/JWT tokens, Iraqi mobile numbers, emails, and 13–16 digit card numbers validated by the **Luhn mod-10 checksum** (`_luhn_valid`), redacting matched middle characters (`_mask_secret`).
8. **Tamper-Evident Hash Chain Certificates (`blockchain.py`)**:
   - Computes `doc_hash = SHA-256(text)` and `block_hash = SHA-256(canonical JSON of {cert_id, title, author, institution, originality_score, doc_hash, prev_hash, round(ts, 6)})` inside SQLite `BEGIN IMMEDIATE`. Modifying any field breaks `verify_chain_integrity()`.
9. **SSRF Protection & IP Pinning (`url_inspector.py`, `url_sandbox.py`)**:
   - Rejects non-HTTP(S) schemes, blocks localhost/internal hostnames, resolves DNS with `socket.getaddrinfo`, rejects any non-global/private/loopback/link-local/multicast/CGNAT/`169.254.0.0/16`/`fc00::/7`/`fe80::/10` address (`_is_public_ip`), and connects directly to the validated public IP via `_PinnedHTTPConnection` / `_PinnedHTTPSConnection` (passing original hostname for TLS SNI verification) while manually re-validating every redirect hop (`trace_safe_redirects`) against DNS rebinding.
10. **Authentication, RBAC & Rate Limiting (`dev_console.py`, `db.py`)**:
    - Passwords hashed with **PBKDF2-HMAC-SHA256** (`210,000` iterations, 16-byte random OS salt) and verified via `hmac.compare_digest`.
    - Session tokens are `base64url(payload).base64url(HMAC-SHA256)` (`12h` TTL) checked against DB `active` flag and endpoint role tuples (`owner`, `editor`, `viewer`).
    - Invites store only `SHA-256(raw_token)` and redeem atomically inside `db_transaction`.
    - Rate limiter deletes timestamps older than `60s` and blocks (`429`) when count `>= 30` per IP key.

---

## Section E — Request Flow Examples

### Workflow 1: Scanning a Suspicious Message (`POST /api/analyze`)
1. User enters a message (e.g. `"مبروك ربحت 5000$ اضغط http://paypa1-secure.xyz/login وادخل OTP"`) in React (`src/App.tsx`).
2. Clicking **Analyze** invokes `useAnalyze.ts` → `fetch('/api/analyze', { method: 'POST', body: JSON.stringify({ text, url }) })`.
3. FastAPI (`backend/main.py`) passes middleware checks (`<= 128 KB`), runs `check_rate_limit()` against SQLite, trims `text[:5000]`, and calls `analyzer.analyze_message(...)` directly in Python.
4. `analyze_message` extracts URLs (`extract_urls`), runs `inspect_url_forensics` on each link, normalizes Arabic with `normalize_arabic_with_map`, matches rule phrases from `rules_config.py`, applies dampeners, formats `family_warning` (`ar`/`en`), and builds `evidence_bundle`.
5. FastAPI adds security headers and returns JSON `200 OK`.
6. React renders the score gauge, verdict, Python-precomputed highlighted text (`highlight_segments`), grouped suspicious segments (`grouped_suspicious_segments`), URL forensics, and uses `result.family_warning[lang]` if the user clicks "Copy Family Warning".

### Workflow 2: Detonating a URL in Safe Sandbox (`POST /api/sandbox-url`)
1. User pastes a URL into `UrlSandboxPanel.tsx` → `fetch('/api/sandbox-url', { method: 'POST', body: JSON.stringify({ url }) })`.
2. FastAPI checks rate limit and `get_runtime_settings()["enable_url_sandbox"]`, then calls `url_sandbox.detonate_url_in_sandbox(raw_url)`.
3. Python blocks unsafe schemes (`javascript:`, `file:`, etc.), checks `_resolve_public_host` (blocking private/metadata IPs with `execution_mode="blocked_ssrf"`), performs TLS inspection, and fetches up to `128 KB` over `trace_safe_redirects` (pinned IP, zero cookies, max 6 hops).
4. `_SafeSandboxHTMLParser` passively scans forms, password/OTP inputs, hidden iframes, `meta refresh`, `eval`/`atob`, keyloggers, and Telegram/Discord webhooks—executing zero JS.
5. FastAPI returns the sandbox trace, DOM telemetry, predicted/observed behaviors, and `safety_guarantees`, which React renders.

### Workflow 3: Academic Analysis & Certificate Issuance
1. In `AcademicShield.tsx`, typing captures raw keystroke intervals (`intervalsRef.current`) locally; clicking Analyze posts `text`, `reference_text`, and `behavior` (including `intervals_ms`) to `POST /api/academic/analyze`.
2. Python runs `academic_analyzer.analyze_academic_text()` → `ai_detector.analyze_ai_vs_human()`, 4-gram shingling (`_compute_plagiarism_matches`), and server-side cadence stats (`compute_interval_stats` / `_evaluate_typing_behavior`).
3. If `eligible_for_certificate` is true (`originality >= 70`, `words >= 15`, `plagiarism < 15%`), submitting the form calls `POST /api/certificates/issue` → `blockchain.issue_certificate()` inside SQLite `BEGIN IMMEDIATE` to mint `ACAD-XXXX-XXXXXX`.

---

## Section F — 25 Professor Questions & Memorizable Answers

1. **Why did you refactor the backend so Python handles almost everything through FastAPI instead of Express + `bridge.py`?**
   Originally, Node/Express spawned Python processes via a bridge, adding IPC overhead and duplicating validation logic. Consolidating onto FastAPI lets one Python process handle HTTP routing, validation, security checks, SQLite, and serving the compiled React build directly.

2. **Why choose FastAPI over Flask or Django?**
   FastAPI gives automatic Pydantic request validation, clean type hints, OpenAPI docs, ASGI performance with Uvicorn, and lightweight setup without Django's heavy ORM boilerplate—ideal when integrating directly with custom SQLite transactions and forensics modules.

3. **Why keep React and TypeScript on the frontend at all?**
   React provides a responsive bilingual RTL/LTR interface, smooth animations, and HTML5 `<canvas>` rendering (`shareCard.ts`, `videoScrub.ts`). Keeping small browser-side helpers like live keystroke preview and text length clamping avoids spamming HTTP requests on every keystroke.

4. **How do React and Python communicate in development vs. production?**
   React always calls relative `/api/...` paths using `fetch()`. In development, Vite runs on port `5173` and proxies `/api` to FastAPI on port `8000` (`vite.config.ts`). In production, `npm run build` outputs `dist/`, and FastAPI serves both `/api/*` and `dist/` from a single server.

5. **Why use SQLite instead of PostgreSQL or MySQL?**
   SQLite needs zero external database server installation, runs reliably across Windows and Linux from a single file (`kashf.db`), and with WAL mode (`PRAGMA journal_mode=WAL`) plus `BEGIN IMMEDIATE` transactions handles concurrent reads and serialized writes cleanly.

6. **How does the phishing message detector handle Arabic dialects and obfuscation?**
   `text_utils.normalize_arabic_with_map()` strips diacritics, tatweel (`ـ`), and invisible zero-width characters, unifies Alef/Ya/Ta Marbuta forms, and keeps an `index_map` to exact original characters for UI highlighting while scoring Iraqi/MSA/English phrase rules.

7. **How does the risk scoring avoid false positives on safe messages that mention "OTP" or "urgent"?**
   `analyzer.py` uses context rules: legitimate `"do not share this code"` messages with no links/actions trigger `has_no_share_guard`; soft urgency only scores when paired with risky links or credential demands; and campus/meeting contexts trigger `-20` (`BENIGN_CONTEXT_DAMPENER`).

8. **How does URL analysis catch lookalike brand domains like `paypa1-secure.xyz` or Cyrillic spoofing?**
   `url_inspector.py` decodes `xn--` Punycode, flags mixed Unicode scripts (`Latin` + `Cyrillic`/`Greek`), maps confusables via `CONFUSABLE_MAP`, normalizes leetspeak (`1→l`, `0→o`), splits hyphenated tokens, and computes Levenshtein edit distance against 27 official brands.

9. **Why does URL inspection have 4 classifications (`malicious`, `suspicious`, `no_known_threat`, `unknown`) instead of just "Safe / Dangerous"?**
   Scientific honesty: having valid HTTPS/TLS on a newly seen domain does not prove it is safe. Unseen domains without official brand status or Threat Intel hits stay `unknown`, and clean Threat Intel results are labeled `no_known_threat` rather than guaranteed safe.

10. **What is SSRF and how does Kashf prevent it?**
    Server-Side Request Forgery tricks the backend into probing internal LAN services or cloud metadata (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`). `_resolve_public_host` blocks local names and private/reserved IPs via `ipaddress` before connecting, and re-checks every redirect hop.

11. **What is DNS rebinding and how does IP pinning stop it?**
    In DNS rebinding, an attacker's domain resolves to a public IP during validation, then swaps to `127.0.0.1` right before the HTTP connection opens. `_PinnedHTTPConnection` and `_PinnedHTTPSConnection` connect directly to the already-validated IP socket while still verifying TLS certificates against the hostname via SNI.

12. **How does the Safe URL Sandbox inspect dangerous pages without infecting the server?**
    `url_sandbox.py` never launches a browser or executes JavaScript. It caps downloads at `128 KB`, discards all `Set-Cookie` headers, writes zero files to disk, and parses HTML tags statically using Python's `HTMLParser` plus regex checks for obfuscation or webhook URLs.

13. **How are Threat Intelligence APIs integrated without exposing API keys or slowing down requests?**
    Keys live only in server environment variables (`.env`), checked via `ThreatSourceResult` (`not_configured` if missing), and the 3 feeds (Google Safe Browsing, VirusTotal, OpenPhish) are queried in parallel using `ThreadPoolExecutor(max_workers=3)` with strict timeouts.

14. **How does Developer Console authentication work?**
    Users log in via email and password checked against a **PBKDF2-HMAC-SHA256** hash (`210,000` iterations + random 16-byte salt) using `hmac.compare_digest`. On success, the server issues a signed Bearer session token.

15. **How are session tokens signed and verified without external JWT libraries?**
    `dev_console.py` constructs `base64url(JSON_payload).base64url(HMAC-SHA256(secret, payload))` with a `12-hour` expiration, verifies the signature in constant time with `hmac.compare_digest`, and confirms the user is still `active` in SQLite.

16. **How does RBAC restrict actions across `owner`, `editor`, and `viewer`?**
    Every protected route calls `_require_dev_role(request, allowed_roles)`. `viewer` can read the overview (with other emails redacted), `editor` can update thresholds/toggles and domain allowlist/blocklist rules, and only `owner` can create invite tokens or revoke/change team roles.

17. **How does the one-time Owner bootstrap avoid insecure default passwords?**
    No default password exists in code. Initializing the first Owner (`POST /api/dev/bootstrap`) requires `KASHF_DEV_BOOTSTRAP_KEY` configured in `.env`, verifies it with `hmac.compare_digest`, and locks itself (`409 Conflict`) once `dev_users` has one row inside a `BEGIN IMMEDIATE` transaction.

18. **How are academic originality certificates protected against tampering?**
    Each certificate stores `doc_hash = SHA-256(text)` and `block_hash = SHA-256(canonical JSON including prev_hash)` in `ledger_blocks`. If anyone alters a score, title, or timestamp directly in SQLite, `verify_chain_integrity()` detects the mismatch immediately.

19. **Does your AI detector use a large neural LLM? How does it actually work?**
    No—being transparent, it does **not** use a neural LLM. It computes 10 stylometric metrics plus cross-entropy from smoothed char-3gram/word-2gram models, runs an L2-regularized logistic regression classifier per language (`ar`/`en`) with leave-one-out Platt calibration, and outputs `Inconclusive` for `< 35` words or borderline/conflicting probabilities.

20. **How does plagiarism detection work and what is its honest limitation?**
    It normalizes text and computes 4-word shingling overlap (`%` and Jaccard) against an attached reference text and 3 built-in sample passages. An explicit limitation is surfaced explaining it checks local text only, not the open web.

21. **How does the DLP scanner detect credit cards without flagging student IDs?**
    `scan_dlp_content` matches 13–16 digit candidates and filters them through `_luhn_valid()` (Luhn mod-10 checksum) before reporting, and always masks detected secrets (`_mask_secret`) so raw passwords or keys are never echoed back.

22. **How do you validate that detection rules didn't regress?**
    `backend/evaluate_models.py` runs out-of-sample confusion-matrix evaluations on held-out `eval_datasets.py` strictly disjoint from `ai_training_corpus.py`, checking precision, recall, F1, false-positive rate, and Brier calibration score (`0.0633`).

23. **How does persistent rate limiting work?**
    `db.check_rate_limit()` cleans timestamps older than 60 seconds for `"api:<client_ip>"` inside a `BEGIN IMMEDIATE` transaction and rejects requests with HTTP `429` once 30 requests exist in the window, persisting across server restarts.

24. **How did you verify security and concurrency?**
    `backend/test_security_audit.py` tests SSRF targets (`127.0.0.1`, IPv6 `::1`, `::ffff:127.0.0.1`, `169.254.169.254`, `100.64.0.1`), 302 redirect traps to localhost, 6-thread concurrent certificate minting + SQLite tampering detection, DLP Luhn/masking, Gemini `x-goog-api-key` header usage, and 429 limits.

25. **How does the app enforce consistent errors and prevent oversized payloads?**
    FastAPI middleware rejects requests exceeding `128 KB` with HTTP `413` before route execution, custom exception handlers normalize Pydantic validation errors to HTTP `400` and `DevAuthError` to `401`/`403`/`409`/`503`, and an `/api/{full_path:path}` catch-all returns JSON `404` so React SPA fallback never masks missing API routes.
