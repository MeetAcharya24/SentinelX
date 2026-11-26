# TASKS.md
_Phased checklist with status and acceptance criteria. Update status inline as work lands — don't restate PROJECT_CONTEXT.md here, link to it._

## Phase 0 — Discovery & plan — ✅ DONE (2026-11-16)
- [x] Lock stack, constraints, safety boundaries
- [x] Lock visual direction (structure from reference mockups + craft decisions in DECISIONS.md)
- [x] Resolve LLM provider / license / deployment topology decisions
- [x] Create context files (this set)
- **Acceptance:** all six context files exist and are internally consistent; no open blocking question remains for Phase 1.

## Phase 1 — Foundation — ✅ DONE (2026-11-16)
- [x] Scaffold frontend (Next.js + TS + Tailwind + shadcn/ui) and backend (FastAPI) project structure
- [x] Env/config handling wired to `.env.example`
- [x] `/health` endpoint, error handling, logging
- [x] Baseline tests (pytest for backend, minimal frontend test)
- [x] Documented local run commands in README
- **Acceptance:** a clean clone runs both frontend and backend locally using only documented README commands.
- **Verified:** backend 18 tests / 100% coverage, ruff clean (dependency install also checked in a fresh venv from `requirements-dev.txt`); frontend 10 tests, typecheck, lint, production build pass; both servers run together and the status card renders live `/health` data in a browser.
- **Carried forward:** `npm audit` reports moderate advisories in dev-only lint tooling — review in Phase 6. Git repository not yet initialised.

## Phase 2 — Data & ML — ✅ DONE (2026-11-16)
- [x] Verify CICIDS2017/UNSW-NB15 license, availability, schema, size; pick primary dataset — **done 2026-11-16: UNSW-NB15, see DECISIONS.md and DATA_DICTIONARY.md**
- [x] Download the two UNSW-NB15 CSVs per DATA_DICTIONARY.md, add the download step to the README, preprocess + reuse the dataset's own train/test split (no need to re-split) — **done 2026-11-16:** files in `data/unsw-nb15/` (git-ignored), `python -m app.ml.check_data` verifies them; loader/validation in `backend/app/ml/dataset.py`, preprocessor in `preprocessing.py`
- [x] Baseline model(s) trained; metrics reported honestly (precision/recall/F1/confusion matrix, class imbalance noted) — **done 2026-11-16:** `python -m app.ml.train` (untuned, seed 42, testing split 55.1% attacks). Random Forest: precision 0.819, recall 0.986, F1 0.895, false positive rate 0.266. Isolation Forest in novelty mode (fitted on the 56,000 normal-labelled training rows only, per DECISIONS.md): precision 0.820, recall 0.363, F1 0.504, false positive rate 0.098; it flags 73.7% of Generic attacks but under 20% of every other category. Gradient Boosting not yet tried.
- [x] Model persistence + inference endpoint — **done 2026-11-16:** `python -m app.ml.train` saves the Random Forest (18 MB, git-ignored) with its test metrics; `POST /api/v1/network/score` returns probability + flag per flow, 503 with instructions when untrained. Checked live: API scores equal offline scores, and all 257,673 published flows pass request validation. Not yet: rate limiting, authentication (Phases 5–6).
- [x] Small safe sample/synthetic demo generator (not bundled as a huge dataset in git) — **done 2026-11-16:** `python -m app.ml.demo_flows` writes 1–100 seeded synthetic flows from five hand-written profiles, labelled `"demo": true`; no dataset rows copied, nothing generated is committed. Checked against the trained Random Forest (100 flows each for seeds 1, 7, 42): the three ordinary profiles score 0.00–0.04, `unanswered_dns_burst` 1.00, `slow_small_session` 0.52–0.90. Not yet: the scoring response does not carry the demo label, so the interface must (Phase 4).
- **Acceptance:** inference endpoint returns a score for a sample input; reported metrics are from an actual run, not asserted.

## Phase 3 — Security analysis — ◐ IN PROGRESS
- [x] Log ingestion + validation against the draft schema in DATA_DICTIONARY.md — **done 2026-11-16:** `POST /api/v1/logs/validate` accepts CSV or a JSON array, checks size and content type before parsing, then validates every row against the final schema (now in DATA_DICTIONARY.md); one bad row rejects the file with the first 20 problems by row and field. Validator in `backend/app/ingestion/logs.py`, synthetic sample `samples/demo_security_log.csv`. Validation only, per ARCHITECTURE.md: raw logs are not stored; persistence arrives with the alerts in item 3.
- [x] Phishing classifier with evidence/signals output — **done 2026-11-26:** `POST /api/v1/phishing/classify` returns label, probability/confidence, rule-based `signals` with triggering values, and the top model terms; links and attachments are never opened. Trained with `python -m app.ml.phishing_train` on Nazario phishing + SpamAssassin ham (corpora, licences and limits in DECISIONS.md). Held-out (1,184 messages, 27.2% phishing): precision 0.997, recall 0.978, F1 0.987, FPR 0.001; optimistic because the classes differ in source and era, and a plain meeting note scored 0.57 in a spot check. `phishing3.mbox` unreadable, not used. Not yet: persisting results as alerts (item 3), cross-corpus evaluation.
- [x] Rule-based + anomaly scoring → alert generation — **done 2026-11-26:** `POST /api/v1/analyze/{network,logs,phishing}` combine the Random Forest and Isolation Forest scores, the phishing classifier with its signals, and rules (failed-login burst, success after failures, known-bad IP/domain lists, event signatures, off-hours changes) into alerts with severity, confidence, evidence (model scores, matched rules, phishing signals) and `created_at`/`occurred_at`; they are stored in SQLite and listed with `GET /api/v1/alerts` (filter by severity, category, status, source, time range, min confidence, demo; sort; paging) and `GET /api/v1/alerts/{id}`. `python -m app.ml.train` now also saves the Isolation Forest (retrain needed). Checked live with the real models: the sample log stores three alerts, 100 demo flows 40. 248 backend tests, ruff clean. Not yet: status changes and notes (item 4), de-duplication, tuned thresholds, real threat-intel lists (Phase 5). Design in DECISIONS.md.
- [ ] Investigation workflow (status, notes, false-positive marking)
- **Acceptance:** uploading a sample log produces at least one evidence-backed alert end-to-end.

## Phase 4 — Frontend — ☐ NOT STARTED
- [ ] Shell (sidebar/topbar) + Dashboard / Alerts / Investigations / Network Analysis / Reports / AI Analyst pages, matching the locked visual direction
- [ ] Every page wired to real backend responses; any demo fixture explicitly labeled as such
- [ ] Loading / empty / error / no-API-key states present on every data view
- **Acceptance:** no chart, card, or table on any page is silently hardcoded — each sources from a real API call or a clearly labeled demo fixture.

## Phase 5 — AI analyst & intelligence enrichment — ☐ NOT STARTED
- [ ] Provider abstraction + Groq integration (per DECISIONS.md) + deterministic fallback
- [ ] Caching + rate limiting
- [ ] Free/public threat-intel lookups with source, timestamp, confidence shown
- **Acceptance:** AI analyst output cites the evidence fields it used and works correctly both with and without an API key configured.

## Phase 6 — Quality & security — ☐ NOT STARTED
- [ ] Tests, type-check, lint, production build all pass — or failures are explicitly documented
- [ ] Dependency review + secret scan clean
- [ ] Threat model + limitations section written
- **Acceptance:** no secret anywhere in git history; critical issues fixed before moving to deployment.

## Phase 7 — Deployment & release — ☐ NOT STARTED
- [ ] Re-verify current Vercel/Render free-tier terms before finalising
- [ ] Deploy frontend + backend; document exact env vars, cold-start behaviour, persistence limitations
- [ ] README, screenshots, architecture diagram, GitHub description, LinkedIn blurb — zero AI-assistant references anywhere
- **Acceptance:** a stranger can clone, run, and understand the project from the README alone; the live demo works or its limitation is documented plainly.
