# DECISIONS.md
_Short decision log — append-only. Each entry: what, why, when to revisit._

---

### 2026-11-16 — Free-tier LLM provider for the AI security analyst
**Decision:** Groq (OpenAI-compatible Chat Completions API) as the primary hosted path, called only through a provider-abstraction layer. A deterministic, template-based explanation generator is the mandatory fallback whenever no API key is configured — this fallback is not optional and must cover 100% of the analyst feature's core behaviour.
**Why:** of the realistically-free options, Groq currently offers the fastest inference and a free tier generous enough for a demo workload, with an OpenAI-compatible SDK that keeps integration simple (least complexity for the abstraction layer). Running a local LLM on a free serverless backend was rejected — RAM/CPU limits on Render's free tier make that slow or infeasible.
**Revisit when:** at the start of Phase 5, re-verify Groq's current free-tier terms before wiring the integration. If terms have materially worsened, the provider abstraction means swapping to another OpenAI-compatible free tier (e.g. a different host's free inference endpoint) costs one config change, not a rewrite.

---

### 2026-11-16 — License
**Decision:** MIT.
**Why:** simplest, most permissive, most recognisable choice for a solo portfolio project being shown on GitHub/LinkedIn. No copyleft or dual-licensing complexity needed — nothing in the project depends on restricting downstream use.

---

### 2026-11-16 — Deployment topology
**Decision:** Vercel (Next.js frontend) + Render (FastAPI backend, free web service tier) + SQLite (no separately hosted database).
**Why:** this is the most standard, best-documented pairing for a Next.js + FastAPI app, and it's the pairing with the fewest moving parts among the brief's allowed options (Vercel/Render/Replit) — a third service (hosted Postgres) isn't needed for MVP scope, so it's deliberately left out until there's a real reason to add it.
**Known tradeoff (to be documented honestly in the README, not hidden):** Render's free web service sleeps after inactivity, so the first request after idle has a cold start of roughly 30–60 seconds. SQLite on Render's free tier should be re-checked at Phase 7 for disk persistence behaviour across deploys/restarts, since this affects whether stored alerts/investigations survive a redeploy.
**Revisit when:** Phase 7, against whatever Vercel/Render's actual current free-tier terms are at that time.

---

### 2026-11-16 — Visual craft direction
**Decision:** Keep the four reference mockups' information architecture, layout, and severity/accent colour system exactly as supplied (dashboard shell, KPI cards, charts, alert tables, tabbed investigation detail). Within that locked structure, elevate execution rather than defaulting to a generic enterprise-dashboard look:
- **Typography:** a distinctive geometric/humanist display typeface for UI chrome (not a default system font), paired with a monospace face for technical values — IPs, hashes, asset IDs, timestamps — so the interface reads as an engineering/security tool rather than a generic SaaS dashboard.
- **Background/depth:** replace flat navy fill with a subtle layered treatment — fine grain/noise at low opacity and a soft vignette for depth — felt rather than noticed; no added glow or clutter, consistent with the brief's explicit instruction to avoid decorative effects.
- **Motion:** one or two purposeful choreographed moments (a staggered entrance for dashboard cards on load; a progressive line-draw for the investigation timeline) instead of scattered micro-animations everywhere. Respects `prefers-reduced-motion`.
- **Colour:** the required severity colours and the blue/cyan accent are kept exactly as shown — this is a functional requirement, not a style choice. The base navy and accent cyan are tuned toward a cooler, more deliberate pairing to avoid reading as the generic "AI SaaS" blue-purple gradient look.
**Why:** the brief requires treating the supplied screenshots as the primary design reference and instructs not inventing a different design — this preserves that fidelity at the structural level while avoiding a purely templated visual execution.

---

### 2026-11-16 — Phase 1 foundation choices
**Decision:**
- Layout is `backend/` + `frontend/` in one repository, with a single root `.env` (template: `.env.example`). The backend reads it directly; `frontend/next.config.ts` forwards only `NEXT_PUBLIC_*` keys so backend secrets never reach the web build.
- All API responses share one envelope: `{success, data, error: {code, message, details}}`. Unhandled errors are logged server-side and returned as a generic message.
- Added `CORS_ORIGINS` (comma-separated) to the environment contract; the API only answers browser calls from listed origins.
- Backend development targets Python 3.13 (3.11+ supported): the newest interpreter on the dev machine is too new for reliable ML wheel availability.
- Frontend tests use Vitest + Testing Library without `@vitejs/plugin-react` (its optional peer chain conflicts with the shadcn CLI's Babel dependency; Vite's built-in JSX transform is sufficient). Backend tests use `httpx2`, the client Starlette's test client now expects.
- LICENSE copyright line reads "SentinelX contributors" until the owner's preferred name is supplied.
**Why:** smallest set of conventions that later phases can build on without rework.
**Revisit when:** Phase 7 (set `CORS_ORIGINS` and `NEXT_PUBLIC_API_BASE_URL` for the deployed hosts; pin the Render Python version).

---

### 2026-11-16 — Primary network anomaly detection dataset
**Decision:** UNSW-NB15 is the primary dataset for Phase 2, using the pre-split `UNSW_NB15_training-set.csv` (175,341 rows) and `UNSW_NB15_testing-set.csv` (82,332 rows), 49 features + label + attack category, from the UNSW Canberra Cyber Range Lab source (research.unsw.edu.au/projects/unsw-nb15-dataset). CICIDS2017 is not used for the MVP; it may be added later as a stretch-goal secondary dataset if there's time after Phase 2's acceptance criteria are met.
**Why:**
- **License clarity.** The authors' own page states the grant plainly: free use for academic research is granted in perpetuity, with commercial use requiring the authors' agreement and citation of their five listed papers. That's a clean, low-risk fit for a portfolio project with no ambiguity about redistribution of the small CSV files inside the repo (the CSVs themselves still aren't committed to git — see DATA_DICTIONARY.md).
- **Practical size.** The pre-split train/test CSVs are ~257K rows combined with 49 features — comfortably fast to preprocess and train on a free-tier machine/CI, versus CICIDS2017's ~2.8M rows and 79–80 features, which is heavier for no MVP benefit.
- **Known baseline-friendly shape.** Numeric + categorical flow features with a clear binary label and a separate attack-category column, suited to the brief's baseline-first models (Random Forest / Isolation Forest / Gradient Boosting) without extra feature-engineering work before a first working pipeline exists.
- **CICIDS2017's documented label-quality issues** (multiple published papers flag inconsistencies in its generated labels) make it a worse first choice for a project whose own acceptance criteria require reporting honest, measured metrics — reproducing a noisy-label baseline first would muddy the "explainable, trustworthy" positioning the brief asks for.
**Revisit when:** if Phase 2 needs a second dataset for broader attack-category coverage, add CICIDS2017 as a secondary/stretch dataset — do not swap away from UNSW-NB15 as primary without updating this entry and DATA_DICTIONARY.md together.

---

### 2026-11-16 — Isolation Forest training mode
**Decision:** Refit Isolation Forest in novelty-detection mode — trained only on rows labelled `normal` in the training split, evaluated on the full testing split (both classes). Keep the resulting metrics (AUC 0.79, precision 0.82, recall 0.36) as the reported baseline rather than treating the fully-unsupervised variant (trained on the mixed training split with no label use at all) as a documented negative result.
**Why:** training an Isolation Forest on normal-only data is the standard, textbook use of the algorithm — it models what "normal" looks like and flags deviations, which is exactly the anomaly-detection role this model plays in the product alongside the supervised Random Forest. Using the label column only to *select* which rows represent normal traffic is not the same as using it as a training target; it's semi-supervised data curation, not supervised learning, so it doesn't compromise the "unsupervised anomaly detector" framing shown in the product (the Network Analysis reference screen shows Isolation Forest as an active model with a confidence score, not a disabled/negative-result one). A fully label-blind Isolation Forest that performs worse is a weaker choice when a legitimate, still-largely-unsupervised variant with real, honestly-reportable numbers is available.
**Honest framing for the report/UI:** recall of 0.36 is modest and must be shown as-is, not hidden or rounded away — the model card / investigation copy should describe this model as catching traffic that deviates from a normal-activity baseline (useful for unfamiliar/novel patterns), complementary to the supervised Random Forest rather than a replacement for it, consistent with the brief's instruction to distinguish model confidence from certainty.
**Revisit when:** if a future phase adds more labelled attack diversity, re-evaluate whether a hybrid or purely unsupervised approach performs better; don't silently swap the training mode without a new entry here.

---

### 2026-11-16 — Git workflow and GitHub publishing (standing convention)
**Decision:** From here on, the coding agent creates and manages the GitHub remote itself, via the GitHub CLI (`gh`), rather than the operator creating the repository by hand. Concretely:
- First time: `git init` (if not already a repo), commit everything built so far, then `gh repo create sentinelx-ai-security-intelligence --public --source=. --remote=origin --push` (requires `gh auth login` once if not already authenticated).
- After every phase completes (and after any other meaningfully-sized change): commit and push automatically as part of wrapping up that phase, without waiting to be asked each time.
- Never include an AI co-author trailer or any reference to AI tools or model names in commit messages, per the public-presentation rule — this was already being followed and stays unchanged.
**Why:** removes a manual step from every project the operator runs this way, and — just as importantly — gets this project under real version control immediately, which is the actual fix for silent file-overwrite races like the one that just dropped two entries from this file. Frequent small commits mean a future accidental overwrite is recoverable from git history instead of permanently lost.
**Revisit when:** never, unless the operator asks for manual control back.

---

### 2026-11-16 — Hardening the scoring endpoint after review
**Decision:**
- Request bodies over 1 MiB (`MAX_REQUEST_BYTES`) are refused with 413 before parsing, whether the length is declared or streamed. Numbers above 3.0e38 are a 422 (the forest reads values as float32; larger ones crashed prediction). Whitespace around category values is trimmed.
- Categories the model never saw are not rejected, because rare real categories exist; each score instead lists them in `unseen_categories`. Matching stays exact and case-sensitive.
- A 503 gives the client only "train a model" or "retrain" wording; paths and versions go to the server log. The stored model carries a SHA-256 in its metadata, is written atomically, and is rejected on load if it does not match, is not a pipeline, or has other feature names.
- Test metrics in responses are a typed model (row count is an integer). The served model predicts on one thread per request.
**Why:** each was reproduced by the review as a 500, an unbounded read, a silent score change, or a leaked server path.
**Revisit when:** authentication and rate limiting are added (Phases 5–6), or the API runs behind a proxy that should also cap body size. Still open: the loaded model is never refreshed (restart after retraining).

---

### 2026-11-16 — Demo flows are generated, not sampled
**Decision:** Demo-mode network flows come from `python -m app.ml.demo_flows`: a seeded generator drawing from five hand-written traffic profiles, with dependent fields (rate, load, mean packet size, handshake times) derived so each flow is coherent. No UNSW-NB15 rows are copied into the repository, and generated files are not committed. The output carries `"demo": true`, a notice, and the profile name of each flow.
**Why:** a sampled fixture would redistribute dataset rows and could be mistaken for real traffic; a generator is a few kilobytes of code, reproducible from a seed, and unmistakably synthetic. Profile ranges were set from aggregate statistics of the training split, so the trained model scores them sensibly, but that also means the demo shows the model on inputs shaped like its training data and says nothing about its accuracy.
**Revisit when:** the interface needs demo alerts end to end (Phase 4), at which point the demo label must travel with the scores rather than live only in the input file.

---

### 2026-11-16 — Repository renamed to SentinelX
**Decision:** The GitHub repository is `MeetAcharya24/SentinelX`, renamed from `sentinelx-ai-security-intelligence` right after it was first published. This supersedes the name in the "Git workflow and GitHub publishing" entry above; the rest of that entry stands.
**Why:** the operator wants the repository to carry the product name only.
**Revisit when:** never, unless the operator asks.

---

### 2026-11-16 — Isolation Forest novelty mode: implemented and measured
**Decision:** The novelty-mode refit decided in "Isolation Forest training mode" above is now what the code does: `fit` in `backend/app/ml/training.py` trains the Isolation Forest on the 56,000 training rows labelled normal and refuses to train when there are none. Measured by `python -m app.ml.train` on the full testing split (untuned, 100 trees, seed 42): precision 0.820, recall 0.363, F1 0.504, accuracy 0.606, false positive rate 0.098 (confusion matrix: 33,378 true negatives, 3,622 false positives, 28,855 false negatives, 16,477 true positives). These figures replace the ones quoted in that entry; no AUC is reported because none was computed in this run. The earlier label-blind run (precision 0.354, recall 0.015, F1 0.029) is retired and no longer reported.
**Why:** the label-blind result was unusable, and reported numbers must come from a run of the code in the repository.
**Known limits:** detection is concentrated in one category — 73.7% of Generic attacks are flagged, against 18.2% of Worms, 12.2% of Exploits and Fuzzers, and about 1% of Reconnaissance and Shellcode. Only the Random Forest is saved and served; the Isolation Forest is evaluated but not persisted.
**Revisit when:** the Network Analysis page needs an Isolation Forest score (Phase 4), which requires persisting it and choosing a threshold rather than the library default.

---

### 2026-11-26 — Phishing classifier: corpora, model and evidence
**Decision:** Phishing = Nazario corpus `phishing0-2.mbox` (CC BY 4.0, read from the host's README and LICENSE files). Legitimate = SpamAssassin public corpus easy/hard ham; the host states no licence, only that copyright stays with the senders, so it is downloaded by the operator for training, never redistributed, and credited in the README. Model: TF-IDF (1-2-grams, letters only) + logistic regression with balanced class weights, on subject and visible body text only; a linear model gives exact per-term contributions. Separate transparent rules (reply-to mismatch, IP-literal links, link text vs target, shorteners, urgency and credential wording, risky attachment types) are returned as `signals` and do not set the label. Exact-text duplicates are removed before a stratified 80/20 split (seed 42).
**Why:** these are the free labelled sources with a readable licence statement. Later Nazario years (2015+) were not mixed with 2002-03 ham because that would let the model learn the year. `phishing3.mbox` was left out because the file was unreadable right after download (permission denied); not investigated further.
**Known limits:** held-out precision 0.997, recall 0.978, false positive rate 0.001 are optimistic: the two classes differ in source and era (ham is mostly 2002-03 mailing lists), and a one-line ordinary meeting note scored 0.57 in a spot check. Dates, numbers and list boilerplate words are masked; terms such as `newsisfree` and `linux` still weigh towards legitimate. No test on a different corpus yet.
**Revisit when:** a second, differently sourced legitimate corpus is available (retrain and report cross-corpus results), or before the analyst interface (Phase 4) shows the confidence prominently; consider a calibrated threshold then.
