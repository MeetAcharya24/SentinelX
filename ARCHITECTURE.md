# ARCHITECTURE.md
_Components, data flow, API boundaries, deployment design._

## High-level shape
```
Next.js frontend (Vercel)  <── REST/JSON ──>  FastAPI backend (Render)  ──>  SQLite + model artifacts (filesystem)
                                                      │
                                                      ├──> Groq (optional, provider-abstracted, free-tier LLM)
                                                      └──> Free public threat-intel sources (cached)
```
No service the operator doesn't already control sits in the critical path of core functionality — both optional outbound integrations have a working no-key/no-network fallback.

## Backend modules
- `api/` — FastAPI routers: `/health`, `/datasets`, `/logs`, `/phishing`, `/alerts`, `/investigations`, `/reports`, `/analyst`
- `ingestion/` — upload validation (size, type, required columns), rejects malformed/oversized input before it reaches processing
- `ml/` — preprocessing, training scripts, model persistence (artifacts excluded from git), inference
- `detection/` — rule-based detectors (repeated failed logins, odd access times, event-rate spikes) plus orchestration of ML-based scoring; produces alert candidates with attached evidence
- `intel/` — threat-intel client(s), response cache, rate limiting, graceful handling of lookup failures (a failed/empty lookup is never treated as "malicious")
- `analyst/` — LLM provider abstraction (Groq today, swappable) + deterministic template fallback; constructs evidence-grounded prompts only from already-detected fields, never raw/unvalidated input
- `storage/` — SQLite models/migrations
- `core/` — config/env loading, logging, structured error handling

## Frontend modules
- `app/(dashboard)/` — routes for SOC Dashboard, Threat Alerts, Investigations, Network Analysis, Assets & Inventory, Reports, AI Security Analyst
- `components/` — shadcn/ui-based primitives, chart components (Recharts), and a single severity chip/badge component that is the one source of truth for severity colour mapping (never redefined per-screen)
- `lib/api/` — typed fetch client against the backend; centralised loading/empty/error state handling so every data view gets these states for free
- a persistent "Demo data" banner component, shown globally whenever the active data source is synthetic/demo rather than a real upload

## Data flow — example: network anomaly detection
1. Operator uploads a dataset/log file.
2. `ingestion/` validates schema and limits.
3. `ml/` preprocesses and runs inference using the persisted baseline model.
4. `detection/` turns scored events into alert candidates with attached evidence (contributing features, scores).
5. Alert/investigation records are written to SQLite.
6. Frontend fetches alerts/investigations through `lib/api/`.
7. On the investigation page, if an AI provider key is configured, `analyst/` explains the evidence already gathered; otherwise the deterministic template does the same job without an external call.

## API boundary rules
- The frontend never computes or fabricates a displayed metric locally — every number/chart/table comes from a backend response, or is an explicitly flagged demo fixture (never silently hardcoded).
- The AI analyst endpoint only ever receives evidence that detection logic already produced; it explains and recommends, it does not independently re-detect or invent findings.
- Threat-intel enrichment is additive and cached — a failed or rate-limited lookup degrades gracefully (shown as "unavailable", never defaulted to a severity judgement).

## Deployment
- **Frontend:** Vercel free tier. Env var for API base URL.
- **Backend:** Render free web service. Cold start after inactivity is expected and documented, not hidden.
- **Storage:** SQLite file alongside the backend service. Persistence behaviour across Render redeploys must be re-verified at Phase 7 against Render's current free-tier terms, and documented honestly either way.

## Security
Controls, their limits and open findings are in [THREAT_MODEL.md](THREAT_MODEL.md). A deployed instance sets `DEMO_WRITE_TOKEN` to write-protect the analyze, status/note and analyst-refresh routes; reads stay open.
