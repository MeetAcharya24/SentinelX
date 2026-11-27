# THREAT_MODEL.md
_What SentinelX protects, from whom, what it does about it, and what it does not do. Facts here were checked against the code on 2026-11-27; anything unverified is labelled so. Update it when a control or a deployment detail changes._

## Scope and assumptions
SentinelX is a single-instance defensive analysis tool: one FastAPI process, one SQLite file, trained models on local disk, an optional hosted analyst (Groq) and two optional threat-intelligence feeds (abuse.ch). It has **no user accounts**. The public deployment (Phase 7) is an interactive demo holding only synthetic, labelled data that resets on every restart; its write token is embedded in the web bundle and is friction, not security (DECISIONS.md, Phase 7). It is not designed to hold real organisational logs on the public internet.

**Assets:** the stored alerts and analyst notes; the host's CPU and memory (free tier, small); the hosted analyst's free quota; the optional keys (`GROQ_API_KEY`, `THREATFOX_API_KEY`, `DEMO_WRITE_TOKEN`); the trained model files.
**Actors considered:** an anonymous internet visitor; a script abusing the public API; an uploader whose file contains hostile text (log lines, email bodies, URLs); a party able to alter files on the host.
**Not considered:** a compromised host or hosting account, a malicious operator, a compromised dependency at install time beyond what the audits below show, denial of service by a network-scale attacker.

## Controls and their limits

### 1. Write-protection gate (`DEMO_WRITE_TOKEN`)
**What it is.** `app/core/writeguard.py`, a route dependency. With the variable unset nothing is checked (local, tests, CI). With it set (minimum 16 characters, enforced at startup), these routes need an `X-Demo-Write-Token` header equal to it, compared in constant time, else `403 write_protected`:
`POST /api/v1/analyze/{network,logs,phishing}`, `PATCH /api/v1/alerts/{id}`, `POST /api/v1/alerts/{id}/analysis/refresh`.
A test enumerates every POST/PATCH/PUT/DELETE route and fails if one is neither gated nor on a recorded exception list, so a new mutating route cannot be added silently ungated.

**Checked:** automated tests (missing, wrong, right, differently-cased and non-ASCII tokens; unset means open; a refused upload stores nothing; the token is not echoed or printed) and a live run against a running server, including the CORS preflight for the header and the token's absence from the server log.

**Limits, stated plainly:**
- **One shared secret, not authentication.** Anyone holding it can do everything the gate covers; there is no per-user identity, audit trail, revocation or rotation other than changing the variable and restarting.
- **It protects writes only.** Every `GET` is open: `/api/v1/alerts` (with notes), alert detail, model metrics and `/health` are readable by anyone. **Do not load real logs or email into a public instance**; assume everything stored there is world-readable.
- **Open, expensive routes that are not gated:** `POST /network/score`, `/phishing/classify` and `/logs/validate` change nothing but run models or parsers. They are rate limited (a POST costs 5 tokens) and nothing else. They were left out of the gate on purpose; add them to `GATED` in `tests/test_write_guard.py` and to the routes if a deployment needs them closed.
- **An open route can spend the hosted analyst's quota.** `GET /alerts/{id}/analysis` generates and caches a report on first view of each alert, calling Groq if a key is set, with no token. The local ceiling (3 calls a minute, 50 a day per process) bounds this, and on exhaustion the built-in explanation is shown, so the cost is lost quota, not money. Gate that route too, or deploy without `GROQ_API_KEY`, if the quota matters.
- **Order of checks.** FastAPI parses a JSON body before it runs route dependencies, so an unauthenticated request with malformed JSON to `/analyze/network` or `PATCH /alerts/{id}` gets `422`, not `403`. Nothing runs and nothing is stored; the body is already capped at 1 MiB. Raw-body routes (`/analyze/logs`, `/analyze/phishing`) refuse with `403` first.
- **Transport and storage of the secret.** It is only as private as the channel: the deployment must serve HTTPS. It lives in the host's environment settings; it must not be in `NEXT_PUBLIC_*` or any frontend file, which is why the web client does not send it. On a protected instance the web UI is therefore read-only (its upload, status and note actions show the `403` message); the operator writes with `curl`.
- **Brute force.** The shared secret is guarded only by the rate limiter (below). A 16-character minimum is a floor; use a random value of 24+ characters.
- **Scope of the 16-character rule:** a weak but long value is not detected.

### 2. Rate limiting
In-memory token bucket per client address, on every route except `/health` (120 a minute, burst 40, POST costs 5; `429` with `Retry-After`).
**Limits:** state is per process, so with more than one instance each allows the full rate and a shared store would be needed; clients behind one NAT share a bucket; the client table is capped at 10,000 and evicts the least recently seen, so a flood from many addresses resets other clients' buckets (it fails open rather than growing without bound); behind a proxy, client identity is correct only with `TRUST_PROXY_HEADERS=true` and a proxy that appends `X-Forwarded-For`, and wrong if that setting is on without such a proxy (forgeable) or off behind one (every client shares the proxy's bucket). It does not defend against slow-body connections. The numbers are untuned starting points. The deployed topology is a single instance (Render free tier, `numInstances` 1), confirmed in Phase 7.

### 3. Persistence on the free host
Alerts, notes, the threat-intelligence cache and analyst reports are one SQLite file. **Tested in Phase 7:** Render's free web service does not keep that file across a redeploy (a note and status change written to the live instance were gone afterwards, and the demo data was reseeded). The deployed demo therefore loses stored alerts and notes at every restart and says so. Trained models are committed to the repository, so a deploy has them.

### 4. Model loading (joblib / pickle)
**Verified in code (2026-11-27).** `joblib.load` is called in exactly two places, `app/ml/persistence.py` (network models) and `app/ml/phishing_model.py` (phishing model), reached from exactly three call sites: `app/api/network.py` and `app/api/alerts.py` (network: `settings.model_dir` and its fixed `isolation_forest` subfolder) and `app/api/phishing.py` (`settings.phishing_model_dir`). No other code deserialises anything with pickle, `marshal`, `shelve` or similar; stored alert evidence and notes are JSON.
- **No request input reaches a model path.** No endpoint accepts a path, filename, URL or model name; the directories come only from `Settings`.
- **The path is not hard-coded, it is operator-controlled.** The defaults are `backend/artifacts/network` and `backend/artifacts/phishing`, written only by the training scripts (`python -m app.ml.train`, `python -m app.ml.phishing_train`) from the locally downloaded datasets. `MODEL_DIR` and `PHISHING_MODEL_DIR` can point elsewhere, so the mitigation holds only while those variables stay unset or point at a directory the operator controls and the process alone can write.
- **The integrity check is weaker than it looks.** Before loading, the file's SHA-256 is compared with the one in the `metadata.json` beside it, and the loaded object must be a scikit-learn `Pipeline` with the expected feature layout. That catches an interrupted save, corruption or a version mismatch. It does **not** stop tampering: anyone who can write the model directory can rewrite the metadata hash too, and the type check runs after unpickling, when any payload has already executed. Treat write access to `backend/artifacts/` as code execution.
- **Phase 7 outcome.** The deployment uses model files committed to the repository, not a training run on the host, so the mitigation now rests on repository and build access: treat write access to the repository or the Render service as code execution.

### 5. AI analyst grounding
The analyst's output (hosted or built-in) is checked mechanically: every statement must cite `alert:<field>` or `evidence:<key>` keys that exist, no address or hostname may appear that is not in the alert, no first-person claim of an action is accepted, and hosted summaries and findings with hedged inference are rejected; it has no write access (a test asserts an "obedient" answer cannot change an alert). **It cannot check that a cited sentence correctly reads its evidence.** A fluent, cited misreading passes. Evidence can contain attacker-controlled text (an email subject, a URL); it is passed as data under instructions to ignore embedded commands, and schema-constrained, but prompt injection is reduced, not eliminated. Suggested checks from the hosted model may include generic defensive steps beyond the alert's evidence. The report is labelled advisory.

### 6. Input handling
Request bodies over 1 MiB are refused before parsing (`413`); content types are checked; log rows are validated against a schema; SQL uses bound parameters; links in emails are listed, never fetched; attachments are listed, never read; the backend never fetches a URL from user input (the only outbound calls are the fixed analyst and feed endpoints). Unhandled errors return a generic message and log the detail server-side. CORS allows only the origins in `CORS_ORIGINS`.

## Findings from the Phase 6 review (2026-11-27)
| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | 10 moderate `npm audit` advisories, all one chain: `minimatch` ReDoS (GHSA-g3hv-75wg-m249) reached through `typescript-eslint` and the `shadcn` CLI | Moderate, dev/build tooling | **Fixed** by `npm audit fix` (lockfile only, no major bump); `npm audit` now reports 0; tests, typecheck, lint and build re-run clean |
| 2 | `pip-audit` on `requirements-dev.txt` and on the installed environment | none | **Clean** (no known vulnerabilities) |
| 3 | Secret scan (gitleaks 8.30.1, all 19 commits on every ref, plus the working tree) | none in history | **Clean.** The working-tree scan flags 226 strings, all in git-ignored or vendored paths (`.venv`, a NumPy test vector, the downloaded phishing corpora, `.next` build cache, the local `.env`); none is tracked and none is in history. No rotation was needed |
| 4 | `GET /alerts/{id}/analysis` can spend hosted-analyst quota without a token | Low (quota only) | **Open, documented** (section 1) |
| 5 | Python requirements are version ranges with no lockfile, so a deployed install can resolve different versions than the ones audited (e.g. FastAPI 0.163.1, scikit-learn 1.9.1 locally). A scikit-learn change also invalidates saved models by design | Low | **Fixed in Phase 7**: `backend/requirements.lock` pins the audited versions and Render installs it |
| 6 | Unauthenticated reads expose all stored alerts and notes | By design for a synthetic-data demo; High if real data is loaded | **Open, documented** (section 1) |
| 7 | Resource leaks: the phishing corpus loader (`app/ml/phishing_data.py`) opened each `.mbox` read-write and never closed it (training CLI only; holds a file lock on Windows); three test fixtures also left SQLite or mailbox handles open. The application's SQLite stores already closed every connection | Low | **Fixed**; the suite now passes with `-W error::ResourceWarning` and no warnings |
| 8 | `/health` and `/docs` are open and `/health` reports whether the analyst and ThreatFox keys are set (booleans, never values) | Low, informational | **Accepted** |

## Out of scope for this review
No penetration test, fuzzing, static-analysis scanner or review of the frontend's response headers and CSP was run. The review covered the dependency, secret, authorisation-gate and model-loading questions above, plus the full automated suites. Findings are decision support, not a guarantee.
