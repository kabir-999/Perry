# Sentinel — Web Application Security Scanner

A full-stack platform for **authorized security assessments** of live web
applications. A user registers a target and gets:

1. A **fast preliminary result** (~1-2s) on submission.
2. A **deep automated assessment** running in the background — one
   centralized crawler (static + real-browser) feeds one Attack Surface
   Inventory, a Test Planner maps the discovered surface to the 12 in-scope
   attacks, the attack modules run, and results stream live over SSE.
3. A deterministic **5-factor risk score** (overall risk = the highest
   confirmed finding's score), reported alongside — but never blended with —
   an independent **assessment confidence** and **coverage** percentage.

Sentinel is a purely **dynamic** web scanner: there is no AI/LLM layer and no
source-code (SAST/secret/dependency) analysis — risk and every status come
solely from deterministic, evidence-based tests.

> **Scope**: only scan applications you own, applications you have explicit
> written authorization to test, local test apps, or intentionally
> vulnerable training apps. Active testing (crafted payloads) requires
> confirming authorization for the target.

```text
Target → Scope validation → Static discovery → Browser/JS execution →
  Dynamic crawling → Network interception → ATTACK SURFACE INVENTORY →
  Authentication discovery → TEST PLANNER → 12 attack modules →
  Evidence validation → Finding dedup → 5-factor risk scoring →
  Coverage → Report
```

## The 12 in-scope attacks

These are the **only** active security tests this version performs.

**MUST**: SQL Injection · Cross-Site Scripting (XSS) · Path Traversal ·
Open Redirect · Security Misconfiguration · Sensitive Information Disclosure ·
Authentication & Authorization.

**ADVANCED**: API Authentication · HTTP Parameter Pollution · File Upload ·
VHost Isolation · Subdomain Takeover.

The architecture is modular (an `attacks/` registry keyed by the 12 canonical
names + a central Test Planner) so more attacks can be added later without
touching the crawler — but nothing outside this list runs today (no NoSQL,
command injection, SSRF, XXE, SSTI, CSRF, deserialization, standalone CORS,
GraphQL/WebSocket-specific attacks, etc.).

## What It Actually Does

- **Discovery**: a bounded static (BeautifulSoup) crawler *plus* a real
  headless-Chromium browser crawler (`playwright install chromium`,
  degrades gracefully if not installed) that renders JS-heavy SPAs
  (Angular/React/Vue) the way a real user's browser would, discovering
  client-side routes a static HTML parse never sees. Every request the
  rendered page's own JS makes — `fetch`/XHR/axios/Angular `HttpClient`, all
  funneling through the same browser network layer — is captured and
  classified as an API/GraphQL/page/asset/WebSocket call **behaviorally**
  (Playwright's own `resource_type` + response content-type), never by
  matching a `/api/`-shaped URL string. JS bundles are additionally mined
  for `fetch(...)`/`axios.*(...)`/`new WebSocket(...)`/GraphQL operation
  literals as endpoint *candidates*, each verified live before being
  reported. Parameters are discovered from query strings, form fields, JSON
  bodies, path-shaped id segments, GraphQL `variables`, and non-standard
  headers/cookies observed in captured traffic — not just query/form pairs.
  Directory/sensitive-file wordlists, OpenAPI/Swagger + common API path
  discovery, subdomain DNS enumeration, and Host-header virtual-host
  discovery all still run as before — guarded against wildcard DNS and
  soft-404/SPA-fallback false positives.
- **Authentication surface detection**: login/register/logout/password-reset
  forms, session cookies, and bearer/JWT-shaped tokens are detected from
  discovered pages/forms/network traffic (never by attempting a login).
  `Authentication/Authorization` reports `NOT_APPLICABLE` only when no such
  surface was found at all — distinct from `NOT_TESTED` (a surface exists
  but wasn't verified) and `INCONCLUSIVE` (verified attempt, ambiguous
  evidence). **Known limitation**: if the login page is reachable only via a
  JS-driven menu/click the browser crawler doesn't happen to trigger (rather
  than a discoverable link or form), Sentinel will honestly report no auth
  surface found rather than guessing one exists.
- **Opt-in authenticated scanning**: a developer-supplied test-account
  credential (`VerifiedTarget.auth_header`, set via
  `POST /api/targets/{id}/credential`) is attached to the browser crawl and
  active tests when a scan sets `authenticated_scan: true`. Sentinel never
  self-registers or generates a credential — the account must already exist
  in the authorized test environment.
- **Two-account authorization (IDOR/BOLA) testing**: with a second
  credential (`VerifiedTarget.auth_header_b`), Sentinel requests a resource
  id actually observed under Account A's session using Account B's session.
  A finding fires only on a byte-identical, reproducible response — never
  against a guessed id or an arbitrary third-party account.
- **Central Attack Surface Inventory + Test Planner**: all discovery sources
  feed one inventory (`inventory.py`) where every endpoint/parameter gets a
  unique internal id (`ep_0001`/`pm_0001`) and a normalized route. The Test
  Planner (`test_planner.py`) then maps that inventory to the 12 attacks —
  SQLi only to injectable params, path traversal only to file-shaped params,
  open redirect only to redirect params/endpoints, file upload only to
  multipart endpoints, etc. No attack module crawls; nothing is tested
  against everything.
- **12 attack modules** (`attacks/`): SQL Injection, XSS (reflected + DOM),
  Path Traversal, Open Redirect, Security Misconfiguration (headers/TLS/
  cookies/CORS/methods/directory-listing/version disclosure), Sensitive
  Information Disclosure (responses/JS/source-maps/errors/exposed files),
  Authentication & Authorization, API Authentication, HTTP Parameter
  Pollution, File Upload, VHost Isolation, and Subdomain Takeover. Each wraps
  evidence-based detection and emits a per-(endpoint,parameter,attack) result.
- **Subdomain Takeover** (detection-only): resolves discovered subdomains'
  CNAME chains, matches known provider fingerprints (GitHub Pages, S3,
  Heroku, Netlify, …) and only reports when a dangling record **and** the
  provider's unclaimed-service signature both hold — never claims/registers
  anything.
- **File upload testing**: discovered multipart endpoints are probed with
  harmless canary files only (never executable content); a bare "upload
  endpoint exists" is never itself a vulnerability.
- **Honest test-status vocabulary**: every matrix row and per-attack summary
  reports `VULNERABLE`, `NOT_VULNERABLE`, `NOT_TESTED`, `INCONCLUSIVE`, or
  `NOT_APPLICABLE` — never a bare pass/fail. A test whose attack surface was
  never discovered reports `NOT_TESTED`, never a silent pass; authentication
  that exists but has no supplied credential is `NOT_TESTED`, never
  `NOT_VULNERABLE`.
- **Test matrix + coverage**: a per-(endpoint,parameter,attack) matrix proves
  which tests actually ran; per-attack coverage reports eligible / tested /
  skipped / inconclusive / vulnerable / not-vulnerable; crawl coverage
  reports discovered-vs-tested counts — discovery is never counted as testing.
- **Deterministic 5-factor risk**: `Risk = 0.35·TypeSeverity + 0.20·Confidence
  + 0.20·Exposure + 0.15·BlastRadius + 0.10·AssetSeverity` per finding;
  **overall risk = the highest confirmed finding's score**. Coverage and
  assessment confidence are reported as separate numbers and never modify the
  risk score — see [ARCHITECTURE.md](./ARCHITECTURE.md#coverage--assessment).
- **Debug mode** (`SCAN_DEBUG=1`): a bracketed-tag trace
  (`[CRAWLER] [BROWSER] [NETWORK] [API] [PARAM] [TEST-PLANNER] [TEST]
  [BASELINE] [COMPARE] [EVIDENCE] [RESULT] [RISK] [COVERAGE]`) so a scan is
  traceable to the exact stage it failed. Zero cost when off.

## Project Structure

```text
web-fuzzer/
├── backend/
│   ├── app/
│   │   ├── main.py             FastAPI app, routers, CORS
│   │   ├── cli.py               CI/CD entrypoint: `python -m app.cli scan`
│   │   ├── config.py            env-driven settings (DB, JWT, Groq, limits)
│   │   ├── database.py          async SQLAlchemy engine/session
│   │   ├── models/              SQLAlchemy ORM models (see Database Schema)
│   │   ├── schemas/              Pydantic request/response schemas
│   │   ├── api/
│   │   │   ├── auth.py           signup / login / me
│   │   │   ├── targets.py        register + verify target ownership
│   │   │   ├── scans.py          create/list/get, SSE stream, findings,
│   │   │   │                    endpoints, subdomains, source-findings,
│   │   │   │                    repositories, events, report, cancel
│   │   │   └── dashboard.py      summary stats
│   │   ├── services/            ~45 modules — discovery, active testing,
│   │   │                        passive checks, repo/secret/SAST/dependency
│   │   │                        analysis, risk model, LLM analyst
│   │   │                        (full breakdown in ARCHITECTURE.md)
│   │   └── tests/               pytest regression suite (backend/tests/)
│   ├── alembic/                 migrations (linear, 12 revisions)
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── components/          Layout, StatCard, SeverityBadge
│   │   ├── pages/                Dashboard, NewScan, ScanDetail, …
│   │   ├── services/api.ts       Axios client + SSE (talks to FastAPI only)
│   │   ├── hooks/
│   │   └── types/
│   └── package.json
│
├── testsite/server.py            loopback-only deliberately-vulnerable app
│                                 used for development/integration testing
├── ARCHITECTURE.md               full pipeline + risk model design
├── .env                (gitignored — your real local config)
├── .env.example
├── .gitignore
└── README.md
```

## Prerequisites

* Python 3.12+
* Node.js 20+
* PostgreSQL 14+ running locally (only needed for the **web** pipeline —
  the CLI needs no database)

## 1. PostgreSQL Setup

Create a database and role for the app (adjust as you like, then update
`DATABASE_URL` in `.env` to match):

```bash
createuser web_fuzzer --pwprompt      # set password: web_fuzzer (or your own)
createdb web_fuzzer --owner=web_fuzzer
```

Or via `psql`:

```sql
CREATE USER web_fuzzer WITH PASSWORD 'web_fuzzer';
CREATE DATABASE web_fuzzer OWNER web_fuzzer;
```

## 2. Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` — see `backend/app/config.py` for the full list; the ones you'll
actually need to set:

```env
DATABASE_URL=postgresql://web_fuzzer:web_fuzzer@localhost:5432/web_fuzzer
JWT_SECRET=replace-with-a-real-secret-in-production
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=your_model_here
GITHUB_TOKEN=optional_pat_for_higher_repo_clone_rate_limits
```

* `GROQ_API_KEY`/`GROQ_MODEL` are read by `config.py`; if unset, the web
  pipeline still runs and reports "AI analysis unavailable" instead of a
  fabricated score. The CLI never calls Groq at all.
* `JWT_SECRET` ships with an obvious dev placeholder — **override it before
  deploying anywhere reachable**.
* **Never** commit `.env` — it's in `.gitignore`. Only `config.py` reads
  secrets, from the environment; the frontend never receives them.

## 3. Backend Setup

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

One-time setup for real-browser crawling (JS/SPA discovery — Angular/React/
Vue apps render their actual routes and API calls only after JS executes,
which a static HTML parse never sees):

```bash
playwright install chromium
```

This is not a hard dependency — if Chromium isn't installed, the browser
crawler degrades gracefully and Sentinel falls back to the static crawler
alone, with a note in scan debug output.

Run the database migrations:

```bash
alembic upgrade head
```

Start the API:

```bash
uvicorn app.main:app --reload
```

* API base: `http://localhost:8000/api`
* Interactive docs: `http://localhost:8000/docs`
* Health check: `GET /api/health`

## 4. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

* Dashboard: `http://localhost:5173`
* API requests to `/api/*` are proxied to `http://localhost:8000` (see
  `vite.config.ts`) — no CORS/env config needed in the frontend.

## 5. Try It (Web Pipeline)

1. Sign up / log in (`/auth/signup`, `/auth/login`) — a `developer` account
   is required to create scans.
2. Register a target (`POST /api/targets`) and complete an ownership
   challenge (DNS TXT / `.well-known` file / meta tag) if you want **active**
   testing; otherwise scans against it stay passive-only.
3. Open the New Scan page, enter a URL you're authorized to test, confirm
   authorization, and submit.
4. Watch it live on the Scan Detail page (SSE): the Fast Scan result appears
   in seconds; the Deep Scan (discovery → 12 attack modules → matrix,
   coverage, and deterministic risk) follows.

## Target Ownership Verification

Registering a target (`POST /api/targets`) issues a one-time verification
token. Prove control of the host via **one** of:

- DNS TXT record at `_sentinel.<hostname>` containing the token
- `/.well-known/sentinel-verification.txt` containing the token
- `<meta name="sentinel-verification" content="<token>">` on the homepage

Then call `POST /api/targets/{id}/verify`. Until verified (or expired —
tokens are valid 90 days), scans against that host run **passive-only**: no
crafted/attacking payloads are sent. `localhost`/loopback/private-IP
targets are exempt.

## Security Scope

This tool is for **authorized security assessments only**:

* applications you own
* applications where you have explicit authorization to test
* local test applications
* intentionally vulnerable training applications

Every scan carries explicit safety controls: max requests, concurrency,
rate limit, request/scan timeouts, and max response size (see the `Scan`
model and `config.py`'s per-stage defaults).

Out of scope, by design, for the entire project: credential stuffing,
password cracking, destructive exploitation, denial-of-service
functionality, persistence mechanisms, malware, unauthorized access, and
uncontrolled mass scanning.

## API

```text
POST   /api/auth/signup                     Create account, returns JWT
POST   /api/auth/login                      Log in, returns JWT
GET    /api/auth/me                         Current user profile

POST   /api/targets                         Register a target, issue verification challenge
POST   /api/targets/{id}/verify             Check the ownership challenge
POST   /api/targets/{id}/credential         Set/clear the test credential for authz checks
GET    /api/targets                         List your targets

POST   /api/scans                           Create + launch a scan (optionally with custom_test_cases)
GET    /api/scans                           List your scans
GET    /api/scans/{scan_id}                 Get one scan
GET    /api/scans/{scan_id}/live            Live snapshot (initial load)
GET    /api/scans/{scan_id}/stream          SSE live-progress stream
GET    /api/scans/{scan_id}/findings        Findings, sorted by risk
GET    /api/scans/{scan_id}/endpoints       Discovered endpoints
GET    /api/scans/{scan_id}/subdomains      Discovered subdomains
GET    /api/scans/{scan_id}/source-findings Per-issue source-code findings
GET    /api/scans/{scan_id}/repositories    Repos associated with the scan
GET    /api/scans/{scan_id}/events          Scan lifecycle event log
GET    /api/scans/{scan_id}/report          Generated JSON report (includes
                                             per-finding verification_status)
POST   /api/scans/{scan_id}/cancel          Cancel a pending/running scan

GET    /api/dashboard/summary               Aggregate stats, scoped to you
GET    /api/health                          Health check
```

All routes except `/auth/*` and `/health` require a `developer` account's
JWT. `/scans/{id}/stream` takes the token as a query param (SSE can't set
headers).

## Database Schema

PostgreSQL via async SQLAlchemy 2.0, UUID primary keys, 12 linear Alembic
migrations. Enum-like columns are plain `String` validated at the
application layer (`app/models/enums.py`), not native Postgres enums.

```text
User ──(1:N)──> Scan ──(1:N, SET NULL)──> AuditLog
User ──(1:N)──> VerifiedTarget

Target ──(1:N, cascade)──> Scan

Scan ──(1:N, cascade)──> Subdomain
Scan ──(1:1, cascade)──> Report
Scan ──(1:N, cascade)──> Repository ──(1:N, cascade)──> SourceFinding
Scan ──(1:N, cascade)──> SourceFinding   (also a direct scan_id FK)
Scan ──(1:N, cascade)──> Finding
Scan ──(1:N, cascade)──> ScanEvent
Scan ──(1:N, cascade)──> DiscoveredEndpoint ──(1:N, cascade)──> Parameter
```

### `users`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| email | String(320) | unique, indexed |
| password_hash | String(128) | bcrypt; plaintext never stored |
| display_name | String(120) | default `""` |
| role | String(16) | `developer` \| `customer` |
| is_active | Boolean | default `True` |
| created_at | DateTime(tz) | |

### `verified_targets`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| user_id | UUID FK → users | cascade delete, indexed |
| hostname | String(255) | indexed |
| verification_status | String(32) | `UNVERIFIED`\|`VERIFICATION_PENDING`\|`VERIFIED`\|`VERIFICATION_FAILED`\|`EXPIRED` |
| verification_method | String(16) | `dns` \| `http` |
| verification_token | String(128) | per-target nonce, never logged |
| last_error | Text | |
| verified_at / verification_expires_at | DateTime(tz), nullable | |
| active_testing_enabled | Boolean | default `False` |
| auth_header | Text, nullable | dev-supplied test credential for authz differential checks; never logged/audited, never returned by any GET |
| created_at | DateTime(tz) | |

### `audit_logs`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| user_id | UUID FK → users, nullable | `ON DELETE SET NULL`, indexed |
| action | String(64) | indexed |
| target | String(255) | |
| result | String(32) | |
| detail | Text | |
| created_at | DateTime(tz) | |

### `targets`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| base_url | String(2048) | |
| hostname | String(512) | indexed |
| authorization_confirmed | Boolean | default `False` |
| allowed_domains | Text | comma-separated in-scope hostnames |
| notes | Text | |
| created_at | DateTime(tz) | |

### `scans`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| target_id | UUID FK → targets | cascade delete |
| user_id | UUID FK → users, nullable | cascade delete, indexed |
| status | String(32) | `ScanStatus` enum (see below) |
| modules | Text | comma-separated enabled modules |
| max_requests / concurrency / rate_limit_per_second / request_timeout_seconds / scan_timeout_seconds / max_response_bytes | numeric | per-scan safety limits |
| requests_made | Integer | |
| error_message | Text | |
| fast_result_json / initial_risk | Text/String | fast-scan output |
| fast_scan_homepage_text / fast_scan_homepage_url | Text/String | cache to avoid refetching |
| repo_info_json / repo_url | Text/String(2048) | linked repo, if any |
| passive_only | Boolean | default `False` |
| custom_test_cases_json | Text | user-defined test cases for this scan (JSON list), only executed when active |
| scan_type | String(32) | `LOCAL_CODE`\|`CI_CD`\|`AUTHORIZED_DEPLOYMENT`\|`PASSIVE_WEB` |
| authorization_status | String(32) | target verification state at scan time |
| final_risk | String(16) | |
| deep_progress / urls_discovered / apis_discovered / parameters_discovered / subdomains_discovered / security_checks_completed / findings_count | Integer | live progress counters |
| ai_status / checks_done_json | String/Text | |
| ai_analyzed | Boolean | risk_score/level authoritative only when `True` |
| ai_error / ai_summary / ai_recommendation | Text | |
| risk_score | Integer | 0–100, set only by the AI analyst |
| risk_factors_json / test_results_json | Text | |
| sentinel_risk_json | Text | Sentinel Risk Model v1 output (score, band, contributors) |
| created_at / started_at / completed_at | DateTime(tz), nullable except created_at | |

### `scan_events`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete |
| event_type | String(64) | |
| message | Text | |
| created_at | DateTime(tz) | |

### `discovered_endpoints`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete |
| url | String(2048) | |
| method | String(16) | default `GET` |
| source / discovery_method | String(64) | |
| status_code | Integer, nullable | |
| content_type | String(256) | |
| response_size | Integer, nullable | |
| created_at | DateTime(tz) | |

### `parameters`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| endpoint_id | UUID FK → discovered_endpoints | cascade delete |
| name | String(256) | |
| param_type | String(32) | `query`\|`form`\|`json`\|`header` |
| example_value | Text | |

### `subdomains`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete |
| hostname | String(512) | |
| resolved_ip | String(64) | |
| source | String(64) | default `dns_bruteforce` |
| created_at | DateTime(tz) | |

### `findings`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete |
| title | String(256) | |
| category | String(128) | |
| severity | String(32) | `Severity` enum |
| confidence | String(32) | `Confidence` enum |
| url | String(2048) / method / parameter | |
| evidence / request_summary / response_summary / description / impact / remediation | Text | |
| risk_score | Float | deterministic score |
| llm_verdict / llm_confidence / llm_explanation / llm_false_positive_reason | nullable | LLM enrichment |
| fingerprint | String(512), indexed | stable across scans of the same target; used for OPEN/REGRESSED/UNVERIFIED remediation tracking in the report |
| created_at | DateTime(tz) | |

### `reports`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete |
| format | String(16) | `html`\|`pdf`\|`json` |
| file_path | Text | |
| created_at | DateTime(tz) | |

### `repositories`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete, indexed |
| provider | String(16) | `github`\|`gitlab` |
| owner / name / url | String | |
| confidence | Float | |
| status | String(32) | `discovered`\|`analyzed`\|`skipped`\|`error` |
| files_analyzed | Integer | |
| error_message | Text | |
| created_at | DateTime | |

### `source_findings`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | cascade delete, indexed |
| repository_id | UUID FK → repositories, nullable | cascade delete, indexed |
| finding_type | String(64) | `hardcoded_secret`\|`env_secret`\|`sql_injection`\|... |
| file / line | String(512) / Integer | |
| severity / confidence | String(32) | |
| evidence | Text | always redacted |
| secret_type / redacted_value / code_context | String/Text | |
| package / version / ecosystem / advisory_id / fixed_version / classification / vulnerable_range | String | dependency-finding fields |
| is_direct / is_used | Boolean | |
| externally_reachable | String(64) | |
| created_at | DateTime | |

### Enums (`app/models/enums.py`)
| Enum | Values |
|---|---|
| `ScanStatus` | `queued → fast_scanning → initial_result_ready → deep_scanning → ai_analysis → completed`, terminal `failed`/`cancelled` (plus legacy `pending`/`running`) |
| `UserRole` | `developer`, `customer` |
| `RiskLevel` | `critical`, `high`, `medium`, `low`, `minimal` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `Confidence` | `confirmed`, `potential`, `uncertain`, `false_positive` |
| `DiscoveryMethod` | `crawler`, `directory_scan`, `api_discovery`, `robots_txt`, `sitemap`, `manual` |
| `ReportFormat` | `html`, `pdf`, `json` |

## Limitations

Honestly, not aspirationally — these are the current, real edges:

- **12 attacks only.** This version runs exactly the 12 attacks listed at the
  top and nothing else — no NoSQL/command injection, SSRF, XXE, SSTI, CSRF,
  deserialization, standalone CORS, or GraphQL/WebSocket-specific attacks.
  The `attacks/` registry + Test Planner make adding one later a local change,
  but none run today.
- **No source-code or AI analysis.** Sentinel is purely dynamic: no SAST,
  secret, or dependency scanning, and no LLM. Every status and the risk score
  come only from deterministic, evidence-based dynamic tests.
- **Auth/authz testing** requires a developer-supplied credential
  (`VerifiedTarget.auth_header`, opt-in via `authenticated_scan: true`).
  Without one, an authentication surface that exists is reported `NOT_TESTED`
  — never guessed, never `NOT_VULNERABLE`. Two-account IDOR/BOLA needs a
  second credential (`auth_header_b`) and only fires on a reproducible,
  byte-identical cross-account read.
- **File upload testing** only ever sends inert canary content (never an
  executable payload) and reports only demonstrated impact.
- **Subdomain takeover is detection-only**: it reports a takeover only when a
  dangling record and the provider's unclaimed-service signature both hold,
  and never claims or registers the dangling service.
- **Browser crawling is discovery-bounded, not exhaustive**: it follows
  same-origin links and reads the rendered DOM's forms, but does not open
  menus, scroll-triggered content, or multi-step flows. A login page reachable
  only through such interaction may not be discovered — Sentinel then reports
  authentication honestly as not-found rather than guessing.
- **No self-service registration**: Sentinel never creates a test account on
  a target — a human creates it once in the authorized environment and
  supplies the session.

## Running Tests

```bash
cd backend
PYTHONPATH=. pytest -q
```

## No Docker

This project intentionally runs without Docker at this stage. Use the
local setup steps above (`uvicorn` + `npm run dev` + a local PostgreSQL
instance) for the web pipeline; the CLI needs neither.

## Further Reading

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full pipeline diagram, the
Sentinel Risk Model's scoring rules, and a log of recent robustness
hardening (false-positive/negative fixes across secret detection,
dependency scanning, discovery, and correlation).
