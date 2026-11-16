# SentinelX

Defensive security analytics for authorised logs and network datasets. SentinelX
ingests security data you are permitted to inspect, detects suspicious patterns
with machine learning and transparent rules, prioritises alerts, and explains
the evidence behind each finding.

> **Project status: early development.** The application foundation (API
> service, web client, configuration, tests) is in place. Detection pipelines
> and the analyst interface are being built in the order listed under
> [Roadmap](#roadmap); nothing below is described as working until it is.

## Planned capabilities

- Network anomaly detection on public intrusion-detection datasets
- Security log analysis (failed-login bursts, unusual access patterns)
- Phishing email classification with the contributing signals shown
- Threat-intelligence enrichment from free public sources
- Alert triage and investigations with evidence, timeline, and analyst notes
- Optional AI analyst that explains already-detected evidence, with a built-in
  fallback that needs no API key
- Reports and model-performance analytics

## Architecture

```
Next.js web client  <── REST/JSON ──>  FastAPI service  ──>  SQLite + model artifacts
```

| Path | Contents |
|---|---|
| `backend/app/api` | HTTP routers |
| `backend/app/core` | Configuration, logging, structured error handling |
| `backend/app/{ingestion,ml,detection,intel,analyst,storage}` | Pipeline modules (in progress) |
| `frontend/app` | Routes |
| `frontend/components` | UI components |
| `frontend/lib/api` | Typed API client and request-state handling |

See [ARCHITECTURE.md](ARCHITECTURE.md) for data flow and API boundary rules.

## Tech stack

- **Frontend:** Next.js, TypeScript, Tailwind CSS, shadcn/ui
- **Backend:** Python, FastAPI, Pydantic
- **Data and ML:** pandas, scikit-learn
- **Storage:** SQLite
- **Tests:** pytest, Vitest, Testing Library

## Local setup

Prerequisites: Python 3.11+ and Node.js 22+.

### 1. Configure

```bash
cp .env.example .env
```

The defaults work as-is. Every API key is optional; leave them blank to run
fully offline.

### 2. Backend (http://localhost:8000)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

Check it: `curl http://localhost:8000/health`. Interactive API docs are at
`http://localhost:8000/docs`.

### 3. Frontend (http://localhost:3000)

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The home page shows a system status card that reads from the API.

### 4. Dataset (needed for model training only)

Network anomaly detection is trained on
[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset). The data
is not stored in this repository; download it once from the publisher:

1. Open the project page above and follow its link to the dataset folder.
2. Go to `CSV Files` → `Training and Testing Sets` and download
   `UNSW_NB15_training-set.csv` (about 32 MB) and `UNSW_NB15_testing-set.csv`
   (about 15 MB).
3. Put both files in `data/unsw-nb15/` at the repository root.
4. Confirm they are in place:

   ```bash
   cd backend
   python -m app.ml.check_data
   ```

The API and web client start without the dataset; the data-dependent tests are
skipped until it is present.

To train the baseline detectors, print their metrics on the testing split, and
save the Random Forest to `backend/artifacts/network/` (about 15 seconds on a
laptop; the folder is git-ignored):

```bash
python -m app.ml.train
```

### 5. Score network flows

With a trained model saved, the API scores flows described by the 42 features of
the UNSW-NB15 training files (see `backend/app/ml/schema.py` for the list):

```bash
curl -X POST http://localhost:8000/api/v1/network/score \
  -H "content-type: application/json" -d @flows.json   # {"flows": [{...}, ...]}
```

To try it without preparing flows by hand, generate synthetic ones (from
`backend/`, 1 to 100 flows; the same seed gives the same file):

```bash
python -m app.ml.demo_flows --count 20 --seed 7 --output flows.json
```

These flows are made up from five hand-written traffic profiles (a web request,
a DNS lookup, a TCP session, a burst of unanswered DNS queries, and a slow TCP
session with small replies). They are not captured traffic and contain no
dataset rows. The file says so itself (`"demo": true` and a notice), lists the
profile of each flow under `profiles`, and can be posted as it is. The scoring
response does not repeat the demo label, so keep track of which results came
from demo input.

Up to 100 flows per request, and bodies over 1 MiB are refused with `413`
before being parsed. Each result has an `attack_probability` and an `is_attack`
flag at the fixed 0.5 threshold, plus `unseen_categories`: the categorical
fields (`proto`, `service`, `state`) whose value the model never saw in
training, which it scores as if rare. Matching is exact, so `TCP` is not `tcp`.
The response repeats the model's measured test-split metrics, including its
false positive rate. Without a usable trained model the endpoint answers `503`
with the command to run. The model is loaded on first use, so restart the API
after retraining.

Models are stored with joblib (pickle): only load files you trained yourself.

### Tests and checks

```bash
# backend/
pytest --cov
ruff check . && ruff format --check .

# frontend/
npm test
npm run typecheck
npm run lint
npm run build
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test`, or `production` |
| `DATABASE_URL` | `sqlite:///./sentinelx.db` | SQLite database location |
| `LOG_LEVEL` | `info` | Backend log level |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated origins allowed to call the API |
| `MAX_REQUEST_BYTES` | `1048576` | Largest request body the API accepts |
| `DATA_DIR` | `<repository>/data` | Folder holding downloaded datasets |
| `MODEL_DIR` | `backend/artifacts/network` | Folder holding the trained network detector |
| `LLM_PROVIDER` | `groq` | Hosted model provider for the optional AI analyst |
| `GROQ_API_KEY` | _(blank)_ | Optional; blank uses the built-in explanations |
| `THREAT_INTEL_API_KEY` | _(blank)_ | Optional; blank disables enrichment |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` | API URL used by the web client |

The web client only ever receives `NEXT_PUBLIC_*` values; backend keys stay on
the server.

## Roadmap

1. Foundation — API service, web client, configuration, tests ✅
2. Data and ML — dataset selection, preprocessing, baseline models, inference
3. Security analysis — log ingestion, phishing classifier, alert generation
4. Analyst interface — dashboard, alerts, investigations, network analysis
5. AI analyst and threat-intelligence enrichment
6. Quality and security review
7. Deployment

Screenshots and the live demo link will be added as those stages land.

## Baseline results

Untuned baselines, trained on the published UNSW-NB15 training split and scored
once on the published testing split (82,332 flows, 55.1% attacks). "Attack" is
the positive class.

| Model | Precision | Recall | F1 | False positive rate |
|---|---|---|---|---|
| Random Forest (supervised) | 0.819 | 0.986 | 0.895 | 0.266 |
| Isolation Forest (novelty detection) | 0.820 | 0.363 | 0.504 | 0.098 |

The Isolation Forest is fitted only on the 56,000 training flows labelled
normal and flags flows that do not look like them. The labels choose those rows
and are not a training target.

Reading these honestly:

- The Random Forest misses few attacks but flags about one in four normal flows,
  which is too noisy for alerting as it stands.
- The Isolation Forest misses most attacks (recall 0.363) while flagging about
  one normal flow in ten. Nearly all of what it catches is one category: it
  flags 73.7% of Generic attacks but under 20% of every other category, and
  about 1% of Reconnaissance and Shellcode.
- The two splits have different class balance, and results on this dataset say
  nothing about performance on any other network.

## Dataset attribution

UNSW-NB15 was created by the Cyber Range Lab of UNSW Canberra and is free to
use for academic research; commercial use requires the authors' agreement.

> N. Moustafa and J. Slay, "UNSW-NB15: a comprehensive data set for network
> intrusion detection systems (UNSW-NB15 network data set)," Military
> Communications and Information Systems Conference (MilCIS), 2015.

The dataset's project page lists the further papers its authors ask to be
cited.

## Responsible use

SentinelX is a defensive analysis tool for education and for systems you own or
are explicitly authorised to monitor. It does not scan, probe, or act against
any system, and it must not be used to analyse data you are not permitted to
access. Demo data, where present, is synthetic and labelled as such. Findings
are decision support for an analyst, not a security guarantee.

## License

[MIT](LICENSE)
