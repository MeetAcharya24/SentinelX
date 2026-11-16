# PROJECT_CONTEXT.md
_SentinelX — canonical project facts. Treat this file as the single source of truth; update it, don't duplicate it. Last updated: 2026-11-16 (end of Phase 0)._

## Vision
SentinelX is a defensive AI cybersecurity intelligence platform: it inspects authorised security logs and network datasets, detects suspicious behaviour, prioritises alerts, and explains why an event was flagged. It must be a real, working, portfolio-grade application with a genuine detection pipeline — not a static dashboard or a chatbot wrapped around sample data. A clearly labelled demo mode may use synthetic events; real analysis operates only on user-provided, authorised datasets.

## Non-negotiable constraints
- **Zero budget.** Build, test, and deploy using only open-source software and currently-available free service tiers. No paid API credits, subscriptions, or billing-dependent features at any point. Never assume a free tier is permanent — verify current limits before committing to a provider.
- **Defensive-only.** No exploit delivery, malware, credential theft, persistence, stealth/evasion, or automated offensive action. No scanning or probing third-party systems. Packet capture/network collection is limited to systems and traffic the operator owns or has explicit permission to monitor.
- **Demo/live separation.** Simulated data is always clearly labelled and never presented as real attacks or live monitoring.
- **Public presentation.** The GitHub repository, README, source comments, commit messages, documentation, screenshots, and the live site must never mention AI tools, model names, or that an AI assistant helped build it. No AI-generated disclaimers or tool acknowledgements. No fabricated team members, certifications, customers, production usage, or security guarantees.

## Stack (locked — see DECISIONS.md for reasoning)
- **Frontend:** Next.js + TypeScript + Tailwind CSS + shadcn/ui + Recharts
- **Backend:** Python + FastAPI
- **ML/NLP:** Pandas, NumPy, scikit-learn (baselines first: Random Forest / Isolation Forest / Gradient Boosting); PyTorch only if it adds measurable value
- **Storage:** SQLite (portable; no separate hosted DB dependency for MVP)
- **AI analyst:** provider-abstracted, optional, free-tier (Groq) with a mandatory deterministic template fallback when no API key is configured — no key is ever required for core product operation
- **Deployment:** Vercel (frontend) + Render (FastAPI backend, free web service)
- **License:** MIT
- **Tests:** pytest (backend) + minimal frontend tests

## Capabilities (MVP scope)
1. **Network anomaly detection** — CICIDS2017 and/or UNSW-NB15, with preprocessing, feature validation, reproducible training, real metrics (precision/recall/F1/confusion matrix), and explainable results.
2. **Security log analysis** — supported CSV/JSON ingestion; detects repeated failed logins, unusual access times/patterns, suspicious event sequences.
3. **Phishing email classification** — transparent NLP/ML pipeline on pasted/uploaded text or headers; shows the signals behind the prediction; never opens links or executes attachments.
4. **Threat intelligence enrichment** — reputable free/public sources only, within their terms/rate limits; cached, with source, timestamp, and confidence shown.
5. **Alert triage & investigations** — severity, confidence, evidence, filters, incident timeline; analyst can mark false positives, acknowledge, assign status, add notes. Recommendations are defensive only — no automatic blocking, exploitation, or scanning.
6. **AI security analyst (optional)** — explains already-detected evidence and drafts recommendations; cites the event fields/evidence used; states when information is insufficient; never invents telemetry or claims to have taken an action.
7. **Reports & analytics** — investigation export, model performance, alert trends, event categories, false-positive review tools.

## Visual direction (structure locked from reference mockups; craft decisions in DECISIONS.md)
Premium dark SOC interface. Compact left nav, top status bar, 4-up metric cards, network/traffic charts, geo threat map, severity-coded alert table, tabbed investigation detail view (Overview/AI Analyst/Evidence/Timeline/Affected Assets/Notes). Severity colour system (critical/high/medium/low) and the blue/cyan accent are fixed and reused consistently everywhere — badges, tables, and charts never improvise their own palette. Motion is restrained and purposeful only; no fake "live" indicators, no decorative glow or clutter. Full responsive/mobile behaviour, keyboard accessibility, and loading/empty/error states are required on every data view, not optional polish.

## Status
**Phase 1 complete (2026-11-16).** `backend/` (FastAPI: config, logging, error envelope, `/health`) and `frontend/` (Next.js 16, Tailwind 4, shadcn/ui; typed API client, request-state hook, system status card) are scaffolded, tested, and run together locally per the README. Local toolchain: Python 3.13 venv in `backend/.venv`, Node 24. 

**Phase 2 complete (2026-11-16).** Primary dataset is UNSW-NB15 (pre-split training/testing CSVs, downloaded to the git-ignored `data/unsw-nb15/`). `backend/app/ml/` has the column schema, loader with validation, the preprocessor, and baseline training/evaluation (`python -m app.ml.train`; pandas + scikit-learn). Measured on the testing split: Random Forest F1 0.895 with a 26.6% false positive rate; Isolation Forest in novelty mode (fitted on normal-labelled training rows only) precision 0.820, recall 0.363, F1 0.504, false positive rate 0.098. The Random Forest is saved to the git-ignored `backend/artifacts/network/` and served by `POST /api/v1/network/score` (fixed 0.5 threshold, model metrics repeated in each response). `python -m app.ml.demo_flows` writes seeded, fully synthetic flows (five hand-written profiles, labelled `"demo": true`) that the scoring endpoint accepts as they are; the response itself does not carry the demo label. Next: Phase 3 (see TASKS.md).

Conventions established in Phase 1:
- Every API response uses the envelope `{success, data, error: {code, message, details}}`; the frontend unwraps it only in `frontend/lib/api/client.ts`.
- One `.env` at the repository root serves both apps; the frontend build receives only `NEXT_PUBLIC_*` keys from it.
- The installed Next.js version differs from older releases — consult `frontend/node_modules/next/dist/docs/` before using framework APIs.
