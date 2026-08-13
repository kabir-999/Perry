# Sentinel — Web Application Security Scanner

A full-stack platform for **authorized security assessments**. A user
registers a target, proves ownership of it, and gets:

1. A **fast preliminary result** (~1-2s) on submission.
2. A **deep automated assessment** running in the background — discovery,
   active testing, passive/config checks, and (if a repo is linked) static
   source-code analysis — streamed live over SSE.
3. A deterministic **Sentinel Risk Model v1** score (CVSS v4.0 for real
   vulnerabilities, a dedicated 0–100 hardening scale for configuration
   weaknesses) plus one Groq LLM call that explains — never invents or
   re-scores — the findings.

It also ships a **CLI** (`app/cli.py`) that runs the same secret/SAST/
dependency scan and the same risk model against a local checkout, with
severity/risk gates suitable for a CI/CD pipeline — no network target, no
web UI required.

> **Scope**: only scan applications you own, applications you have explicit
> written authorization to test, local test apps, or intentionally
> vulnerable training apps. Active testing (crafted payloads) additionally
> requires proving ownership of the target host — see
> [Target Ownership Verification](#target-ownership-verification).

```text
Web pipeline:
  Target registration → Ownership verification → Fast Scan → Deep Scan
    (Discovery · Active Testing · Passive Checks · Repo Analysis)
    → Sentinel Risk Model → Groq LLM Analyst → Report

CLI / CI-CD pipeline:
  Local checkout → Secrets · SAST · Dependency/OSV scan
    → Sentinel Risk Model → Severity/Risk gate → exit code
```

## What It Actually Does

- **Discovery**: bounded crawler, directory/sensitive-file wordlists,
  OpenAPI/Swagger + common API path discovery, parameter discovery,
  subdomain DNS enumeration, Host-header virtual-host discovery — all
  guarded against wildcard DNS and soft-404/SPA-fallback false positives.
- **Active testing** (only against a verified target): a unified engine
  (`ParamTarget → PayloadStrategy → RequestBuilder → ResponseDiff`) for
  reflected XSS, SQL/NoSQL injection, command injection, path traversal,
  open redirect, and HTTP parameter pollution — adaptive, not brute-forced.
  API-discovered parameters run through this same engine, not just
  crawler-discovered ones. Path traversal also runs against file-shaped
  discovered directory/file paths directly, not only URL parameters.
  Path-traversal and command-injection payloads escalate to a few
  URL-encoded/double-encoded/unicode-overlong variants, but only after the
  plain payload came back negative and only where byte-level encoding is
  meaningful (query/form values, not JSON bodies or headers).
- **File upload testing**: discovered upload endpoints are actually probed
  with harmless canary files (never executable content) to check whether a
  disallowed extension or a path-traversal-shaped filename is accepted, and
  — only if Sentinel can fetch back its own canary — whether the uploaded
  content is served back at all. A bare "upload endpoint exists" is never
  itself reported as a vulnerability.
- **Authentication/authorization testing**: a developer-supplied test
  credential (set via `POST /api/targets/{id}/credential`, never logged or
  returned) lets Sentinel compare an authenticated vs. unauthenticated
  request to the same sensitive-looking endpoint. Without a credential, this
  is reported as explicitly **inconclusive** in the test matrix — never
  assumed safe or vulnerable. This is a heuristic differential check with
  one identity, not a real IDOR/BOLA proof; true IDOR detection only fires
  when the same scan happens to observe two distinct concrete IDs for the
  same parameter (rare — the crawler intentionally collapses ID variation
  during discovery), and reports inconclusive otherwise.
- **User-defined custom test cases**: a scan can include up to 20 ad hoc
  tests (name, path, method, input location, payload, validation condition,
  severity), executed through the exact same request/response/evidence
  pipeline as every built-in active test — scope-checked, budget-shared,
  and severity-capped the same way. Kept separate from the static wordlists.
- **Independent subdomain assessment**: up to a handful of resolved,
  reachable subdomains (bounded, sharing the scan's one request budget) get
  their own not-found baseline, passive header/cookie/CORS checks, and a
  small API/active pass — not just DNS discovery reused as VHost-probe
  candidates. A DNS record alone is never a finding.
- **Passive checks**: security headers, cookie flags, CORS, server-version
  disclosure, directory listing, debug/stack-trace leakage, unauthenticated
  sensitive API endpoints.
- **Source-code analysis** (if a public repo is linked or supplied): secret
  detection (env files + hardcoded, git-tracking aware — see below),
  AST-based taint analysis (SAST), and dependency scanning against OSV.dev
  with strict semver-range validation and *reachability* analysis (is the
  vulnerable symbol actually imported and reachable from attacker input, or
  just present in a manifest?).
- **Correlation**: a source-code finding and a live endpoint it backs are
  matched by route-segment/filename token and merged into one scored issue
  instead of two.
- **Risk scoring**: deterministic, auditable, CVSS v4.0 + hardening-model
  based — see [ARCHITECTURE.md](./ARCHITECTURE.md#sentinel-risk-model-v1).
- **Remediation verification**: each finding carries a fingerprint stable
  across scans of the same target. A report compares against the target's
  last two completed scans and marks each finding `OPEN`, `REGRESSED`
  (fixed, then came back), or `UNVERIFIED` (no scan history yet), plus a
  count of issues fixed since the last scan. Never touches source code.
- **AI layer**: exactly one Groq call per scan, strict Pydantic-validated
  output, explains the deterministic findings — it does not invent evidence
  or set severity.
- **CLI/CI-CD mode**: the same secret/SAST/dependency/risk pipeline, run
  locally or in a pipeline, gated on severity and/or risk-score thresholds.

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
4. Watch it live on the Scan Detail page (SSE): Fast Scan result appears in
   seconds, Deep Scan and the AI analysis follow.

## Try It (CLI / CI-CD)

No database, no server, no ownership verification needed — this scans a
checkout you already have:

```bash
cd backend
PYTHONPATH=. python3 -m app.cli scan <path-to-checkout> \
    --fail-on high --max-risk 70 --json report.json
echo $?   # 0 = passed, 1 = a gate failed, 2 = usage error
```

See [ARCHITECTURE.md § CLI / CI-CD Mode](./ARCHITECTURE.md#cli--cicd-mode)
for the full flag reference and gate semantics, and
[.github/workflows/sentinel.yml](./.github/workflows/sentinel.yml) for a
working GitHub Actions example.

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

- **IDOR/BOLA** mostly reports **inconclusive**. It only fires when the same
  scan happens to observe two distinct concrete values for the same
  parameter *and* a test credential is supplied — the crawler intentionally
  collapses ID variation during discovery, so this is rare by design, not a
  bug.
- **Auth/authz testing** requires a developer-supplied credential
  (`POST /api/targets/{id}/credential`). Without one, it never guesses —
  it reports the test as inconclusive.
- **File upload testing** only ever sends inert canary content (never a
  real executable payload) and only escalates to a "confirmed accessible"
  finding when Sentinel can fetch back its own canary — it does not attempt
  to execute anything it uploads.
- **Custom test cases** are capped at 20 per scan and run through the same
  safety limits as every built-in active test — no elevated privileges.
- **Subdomain assessment** is bounded (`SUBDOMAIN_ASSESS_LIMIT`, default 5)
  and shares the scan's one request budget — it is not a full independent
  scan of every discovered subdomain.
- **Remediation verification** compares fingerprints against the same
  target's last two completed scans only; it does not track a longer
  history, and a check that didn't run in a given scan can't confirm
  something else was actually fixed.
- **Payload encoding** escalates only for path traversal and command
  injection, and only on query/form parameters — XSS/SQLi rely on their
  existing plain-payload set, and JSON body/header values aren't
  byte-level re-encoded the same way query strings are.

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
