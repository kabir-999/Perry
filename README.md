# Web Application Security Fuzzer

A full-stack platform for **authorized security assessments and controlled
lab environments**. It discovers a target's attack surface, runs
non-destructive security checks, and (from Phase 5 onward) uses a Groq-backed
**LLM Security Analyst** to explain scanner findings — never to invent
evidence or decide severity on its own.

> **Scope**: only scan applications you own, applications you have explicit
> written authorization to test, local test apps, or intentionally
> vulnerable training apps. The API refuses to create a scan without an
> exact authorization confirmation statement. See [Security Scope](#security-scope).

## Status: Phase 1

This repository currently implements **Phase 1** of the incremental build
plan: project scaffolding, the FastAPI + PostgreSQL backend, a basic scan
creation API, and a basic React dashboard. Discovery, security checks,
response analysis, risk scoring, the Groq LLM Security Analyst, and report
generation are stubbed out (see docstrings in `backend/app/services/`) and
land in later phases.

```text
Target → Discovery → Security Checks → Response Analysis → Finding
       → Groq LLM Security Analyst → Explanation/Confidence/Impact/Remediation
       → Final Report
```

## Project Structure

```text
web-fuzzer/
├── backend/
│   ├── app/
│   │   ├── main.py            FastAPI app, routers, CORS
│   │   ├── config.py          Env-driven settings (Groq, DB, safety limits)
│   │   ├── database.py        Async SQLAlchemy engine/session
│   │   ├── models/            SQLAlchemy ORM models
│   │   ├── schemas/           Pydantic request/response schemas
│   │   ├── api/                FastAPI routers (scans, dashboard)
│   │   ├── services/
│   │   │   ├── scan_manager.py          implemented (Phase 1)
│   │   │   ├── crawler.py               stub (Phase 2)
│   │   │   ├── directory_scanner.py     stub (Phase 3)
│   │   │   ├── api_discovery.py         stub (Phase 3)
│   │   │   ├── parameter_discovery.py   stub (Phase 3)
│   │   │   ├── subdomain_scanner.py     stub (Phase 3)
│   │   │   ├── vhost_scanner.py         stub (Phase 3)
│   │   │   ├── response_analyzer.py     stub (Phase 4)
│   │   │   ├── vulnerability_engine.py  stub (Phase 4)
│   │   │   ├── risk_engine.py           stub (Phase 4)
│   │   │   ├── llm_security_analyst.py  config wired, analysis stub (Phase 5)
│   │   │   └── report_generator.py      stub (Phase 6)
│   │   └── tests/
│   ├── alembic/                Migrations
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── components/         Layout, StatCard, SeverityBadge
│   │   ├── pages/               Dashboard, NewScan, ScanDetail, …
│   │   ├── services/api.ts      Axios client (talks to FastAPI only)
│   │   ├── hooks/
│   │   └── types/
│   └── package.json
│
├── .env                (gitignored — your real local config)
├── .env.example
├── .gitignore
└── README.md
```

## Prerequisites

* Python 3.12+
* Node.js 20+
* PostgreSQL 14+ running locally

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

Edit `.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=your_model_here
DATABASE_URL=postgresql://web_fuzzer:web_fuzzer@localhost:5432/web_fuzzer
```

* `GROQ_API_KEY` / `GROQ_MODEL` are read by `backend/app/config.py` but not
  yet used for analysis — that ships in Phase 5. Leave them blank if you
  don't have a Groq key yet; the app runs fine without them (Phase 1 has no
  LLM calls).
* **Never** commit `.env` — it's in `.gitignore`. Never hardcode the key in
  source; only `config.py` reads it, from the environment.
* The frontend never receives `GROQ_API_KEY`. All Groq calls happen
  server-side in the FastAPI backend (in later phases).

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

If this is your first migration, generate it first:

```bash
alembic revision --autogenerate -m "phase 1 initial schema"
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

## 5. Try It

1. Open `http://localhost:5173/scans/new`.
2. Enter a target URL you are authorized to test (e.g. a local test app).
3. Check the authorization confirmation box.
4. Submit — this creates a `Target` + `Scan` row and a `scan_created` event.
   No requests are sent to the target yet; discovery/scanning modules land
   in Phase 2+.
5. View it on the Dashboard or at `/scans/{id}`.

## Security Scope

This tool is for **authorized security assessments only**:

* applications you own
* applications where you have explicit authorization to test
* local test applications
* intentionally vulnerable training applications

The API enforces an exact authorization confirmation string
(`"I confirm that I have authorization to test this target."`) before a scan
can be created, and every scan carries explicit safety controls: max
requests, concurrency, rate limit, request/scan timeouts, and max response
size (see `Scan` model and `ScanCreate` schema).

Out of scope, by design, for the entire project: credential stuffing,
password cracking, destructive exploitation, denial-of-service
functionality, persistence mechanisms, malware, unauthorized access, and
uncontrolled mass scanning.

## API (Phase 1)

```text
POST   /api/scans                    Create a scan (requires authorization statement)
GET    /api/scans                    List scans
GET    /api/scans/{scan_id}          Get a scan
GET    /api/scans/{scan_id}/findings Get findings (empty until Phase 4)
GET    /api/scans/{scan_id}/endpoints  Get discovered endpoints (empty until Phase 2/3)
GET    /api/scans/{scan_id}/events   Get scan lifecycle events
POST   /api/scans/{scan_id}/cancel   Cancel a pending/running scan
GET    /api/dashboard/summary        Aggregate stats for the dashboard
GET    /api/health                   Health check
```

## Running Tests

```bash
cd backend
pytest -q
```

## No Docker

This project intentionally runs without Docker at this stage. Use the
local setup steps above (`uvicorn` + `npm run dev` + a local PostgreSQL
instance).

## Roadmap

| Phase | Scope |
|---|---|
| 1 | Scaffolding, basic scan API, basic dashboard *(this repo)* |
| 2 | Target validation, authorization confirmation, crawler |
| 3 | Directory/API/parameter/subdomain discovery |
| 4 | Security checks, response analyzer, finding engine, risk engine |
| 5 | Groq LLM Security Analyst (structured explanation/confidence/remediation) |
| 6 | Attack-surface visualization, live scan progress, reports |
| 7 | Testing and optimization |
