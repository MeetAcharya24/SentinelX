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
| `samples` | Synthetic demo input files |
| `frontend/app` | Routes |
| `frontend/components` | UI components |
| `frontend/lib/api` | Typed API client and request-state handling |
| `frontend/lib/hooks` | Shared hooks, including the reduced-motion preference |

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

Trained models are not stored in the repository: `backend/artifacts/` is
git-ignored, so a fresh clone has none. Run the training commands below once
after setup (`python -m app.ml.train` for network flows and alerts,
`python -m app.ml.phishing_train` for phishing, see step 7), and again after
pulling a change that touches the models. A model saved by an older version is
refused with a `503` that names the command to run. In particular,
`/api/v1/analyze/network` needs the Isolation Forest that `python -m app.ml.train`
has saved since alerts were added, so retrain once if you trained before then.

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

### 6. Validate a security log

The API checks a log file against the log schema before anything else is done
with it. Send the file itself as the request body, as CSV or JSON:

```bash
curl -X POST http://localhost:8000/api/v1/logs/validate \
  -H "content-type: text/csv" --data-binary @samples/demo_security_log.csv
```

| Field | Required | Value |
|---|---|---|
| `timestamp` | yes | ISO 8601 with a UTC offset or `Z`, e.g. `2026-01-12T08:02:11Z` |
| `event_type` | yes | Text up to 64 characters, e.g. `login_failure`, `access` |
| `source_ip` | yes | IPv4 or IPv6 address |
| `status` | yes | `success` or `fail` |
| `user` | no | Text up to 256 characters |
| `asset_id` | no | Text up to 256 characters |

CSV needs a header row with these names; JSON (`application/json`) is an array
of objects with these keys and text values. Other fields are ignored and named
in the response.

A valid file returns a summary: event count, time range in UTC, event types,
status counts, and the number of distinct addresses and users. A file with any
invalid row is refused as a whole with `422`, listing the first 20 problems by
row and field. Other content types get `415`, and files over 1 MiB get `413`.
This endpoint only validates: nothing is stored and no alerts are produced
(see [Generate and list alerts](#8-generate-and-list-alerts)).

`samples/demo_security_log.csv` is a made-up log of 30 events for trying this
out. Its users and assets are invented and its addresses come from the ranges
reserved for documentation; it is not a record of real activity.

### 7. Classify a phishing email

The phishing classifier is trained on public email corpora that are not stored
in this repository. Download them once into `data/phishing/`:

1. Phishing: `phishing0.mbox`, `phishing1.mbox` and `phishing2.mbox` from
   [Jose Nazario's phishing corpus](https://monkey.org/~jose/phishing/)
   (CC BY 4.0, credit Jose Nazario; the messages are hand-classified and may
   contain errors).
2. Legitimate mail: `20021010_easy_ham`, `20030228_easy_ham`,
   `20030228_easy_ham_2`, `20021010_hard_ham` and `20030228_hard_ham` (all
   `.tar.bz2`) from the
   [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/).
   The corpus states no licence; the copyright in each message stays with its
   sender, so it is used here for training only and never redistributed.
   Extract the five archives into `data/phishing/ham/` so it holds the folders
   `easy_ham`, `easy_ham_2` and `hard_ham`.
3. Train (from `backend/`; the model is saved to `backend/artifacts/phishing/`):

   ```bash
   python -m app.ml.phishing_train
   ```

   The files hold real phishing mail. Do not open attachments or follow links in
   them.

Then post one email, with or without headers, as the request body:

```bash
curl -X POST http://localhost:8000/api/v1/phishing/classify \
  -H "content-type: message/rfc822" --data-binary @email.eml
```

`text/plain` is accepted too; other types get `415`, and bodies over 1 MiB get
`413`. Nothing is stored, links are listed but never opened, and attachments
are listed by name but never read. The response has:

- `label` (`phishing` or `legitimate`), `phishing_probability`, and
  `confidence`, the probability of the predicted label at a fixed 0.5 threshold.
- `signals`: rule-based observations with the values that triggered them
  (reply-to domain differs from the sender's, link to a raw IP address, link text
  naming a different site than the link opens, URL shortener, urgency wording,
  requests for credentials or payment details, risky attachment types). They
  explain the message; they do not set the label.
- `model_terms`: the words and phrases in this message that moved the model's
  score the most, towards phishing and towards legitimate.
- The model's measured held-out metrics.

Measured on 1,184 held-out messages (27.2% phishing): precision 0.997, recall
0.978, F1 0.987, false positive rate 0.001. Treat these as an upper bound. The
two corpora come from different sources and years (legitimate mail is from 2002
and 2003, mostly public mailing lists and newsletters), so the model can tell
them apart partly by style and topic rather than by phishing cues. Numbers and
month names are excluded from its features to reduce this, but it remains: an
ordinary short work email can still score as phishing (a one-line meeting note
scored 0.57 in a spot check). These figures say nothing about accuracy on mail
from another source or era. Messages with identical text are removed before the
split. `phishing3.mbox` is not used.

### 8. Generate and list alerts

Alerts combine the detectors into one stored, filterable list. Retrain with
`python -m app.ml.train` first: it now also saves the Isolation Forest next to
the Random Forest (`backend/artifacts/network/isolation_forest/`), and the
network endpoint answers `503` until it exists. Alerts are written to the SQLite
file named by `DATABASE_URL`.

| Endpoint | Input | Alert rules |
|---|---|---|
| `POST /api/v1/analyze/network` | flows, as for `/network/score` | Random Forest probability and Isolation Forest anomaly score |
| `POST /api/v1/analyze/logs` | CSV or JSON log, as for `/logs/validate` | known-bad source address, failed-login burst, event signatures |
| `POST /api/v1/analyze/phishing` | one email, as for `/phishing/classify` | classifier probability, signals, known-bad domain |

Add `?demo=true` when the input is synthetic (generated demo flows, the sample
log) so the stored alerts are labelled as demo. Each endpoint returns how many
items were analysed and the alerts it stored; an input nothing flags stores
nothing. Posting the same input again stores nothing new: an alert whose content
matches one already stored (same category, source, asset, title, time, severity,
confidence and evidence, and the same demo label) is returned as stored, with
its status and notes, and counted in the response's `duplicates` field.

Severity follows fixed rules you can predict, not a measured risk score:

- **Network flow:** both models flag, high. Random Forest alone at probability
  0.9 or more, medium; below that, low. Isolation Forest alone, low with a fixed
  confidence of 40, because it has no probability. Flows have no addresses, so
  the alert source is `flow N` (position in the request).
- **Log:** 5 or more failed logins from one address within 5 minutes, medium; 10
  or more, high; a successful login from that address within 10 minutes of the
  last failure, critical. A known-bad source address, high. A `config_change`
  outside 06:00-20:00 UTC, or an event type that names privilege escalation,
  audit-log tampering or turned-off MFA, medium.
- **Email:** classifier at 0.9 or more with two or more suspicious signals,
  high; 0.9 or more, or any suspicious signal, medium; otherwise low. A link or
  sender on the known-bad domain list raises it one level, and alone gives a
  medium alert even when the classifier does not flag the email.

SentinelX ships no real threat intelligence. The known-bad rules read optional
plain-text lists, one entry per line (`#` starts a comment): `bad_ips.txt`
(addresses or CIDR ranges) and `bad_domains.txt`, from `data/blocklists/` or
`BLOCKLIST_DIR`. Without them those rules never match. To try them,
copy `samples/demo_blocklists/` there; it lists one documentation-range address
and one reserved example domain, both made up.

Every alert has `severity`, `confidence` (0-100), `category`, `source`,
`asset`, `title`, `status` (always `open` for now), `demo`, `created_at` (when it
was detected, UTC), `occurred_at` (when the activity happened, if the input says),
and `evidence`: a list of items, each with a `kind` (`model_score`, `rule_match`,
`phishing_signal`, `model_term` or `caveat`), a name, a description, an optional
value and examples.

List them with `GET /api/v1/alerts`, newest first. Filters: `severity`,
`category` and `status` (repeat a parameter to match any of several), `source`,
`created_from` and `created_to`, `min_confidence`, `demo`. Use `sort=severity`
for the most severe first, and `limit` (up to 200) and `offset` to page; the
response includes the `total` matching. `GET /api/v1/alerts/{id}` returns one.

To work an alert, `PATCH /api/v1/alerts/{id}` with a JSON body holding a
`status`, a `note`, or both (at least one; any other field is refused):

```bash
curl -X PATCH http://localhost:8000/api/v1/alerts/2 -H "content-type: application/json" \
  -d '{"status": "acknowledged", "note": "Checking the VPN logs."}'
```

- `status` is `open`, `acknowledged`, `false_positive` or `resolved`. Any status
  can follow any other, so a mistaken change can be undone.
- `note` is 1 to 2,000 characters. Notes are append-only: they cannot be edited
  or deleted (the database refuses both), each gets its own timestamp, and they
  carry no author because there are no accounts yet.
- The response, `GET /api/v1/alerts/{id}` and the list all include every note,
  oldest first, so the alert detail is the note history.
- Status and note are saved together or not at all; an unknown id is `404`.

With the demo log and the sample blocklists, the API stores three alerts: the
burst of failed logins from `203.0.113.45` (high), the known-bad address
(high) and the 02:51 UTC configuration change from `198.51.100.23` (medium).

### 9. Refresh threat intelligence

Two free abuse.ch feeds can be cached locally and matched against alerts:
Feodo Tracker's recommended botnet command-and-control address list (no key) and
ThreatFox's IP, domain and URL indicators (a free Auth-Key from
[auth.abuse.ch](https://auth.abuse.ch/) in `THREATFOX_API_KEY`; without it only
Feodo Tracker is refreshed).

```
cd backend
python -m app.intel.refresh            # refreshes whatever is due
python -m app.intel.refresh --force    # manual run that ignores the schedule
```

Run it from a scheduler about every six hours. The schedule is enforced in the
job: a feed refreshed in the last six hours is skipped, and a feed whose last
attempt failed is not retried for an hour. The cache is two SQLite tables in the
alert database (`threat_intel_iocs`, `threat_intel_feeds`; see
`DATA_DICTIONARY.md`). When a stored alert's source address (logs) or an email's
sender domain, link hosts, link addresses or link URLs match a cached indicator,
the alert gains a `threat_intel_match` evidence item naming the feed, the
malware family when the feed gives one, and when the cache was last refreshed.
This sits next to the operator-supplied blocklist check and does not change
severity or confidence. Tests use canned feed responses; nothing in them touches
the network. Feodo Tracker's list is currently almost empty (its own banner says
the datasets are empty), so expect few matches from it; see `DECISIONS.md`.

### Interface

With the API running and some alerts stored, `npm run dev` in `frontend/` serves
the dashboard (`/`), alert triage (`/alerts`, which also uploads a log file for
analysis), investigations (`/investigations`, `/investigations/<id>`) and network
analysis (`/network`). Every figure comes from stored alerts or the model
endpoint `GET /api/v1/network/model`. Pages that need data the product does not
keep yet (a geographic map, traffic volume, protocol mix) say so instead of
showing placeholders. Motion respects the operating system's reduced-motion
setting.

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
| `PHISHING_MODEL_DIR` | `backend/artifacts/phishing` | Folder holding the trained phishing classifier |
| `BLOCKLIST_DIR` | `<DATA_DIR>/blocklists` | Folder with optional `bad_ips.txt` and `bad_domains.txt` |
| `LLM_PROVIDER` | `groq` | Hosted model provider for the optional AI analyst |
| `GROQ_API_KEY` | _(blank)_ | Optional; blank uses the built-in explanations |
| `THREATFOX_API_KEY` | _(blank)_ | Optional free Auth-Key from auth.abuse.ch; blank skips the ThreatFox feed (Feodo Tracker needs no key) |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` | API URL used by the web client |

The web client only ever receives `NEXT_PUBLIC_*` values; backend keys stay on
the server.

## Roadmap

1. Foundation — API service, web client, configuration, tests ✅
2. Data and ML — dataset selection, preprocessing, baseline models, inference
3. Security analysis — log ingestion, phishing classifier, alert generation, investigation workflow ✅
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

## Threat-intelligence attribution

Threat intelligence is provided by [ThreatFox](https://threatfox.abuse.ch/) and
[Feodo Tracker](https://feodotracker.abuse.ch/), projects of
[abuse.ch](https://abuse.ch/). ThreatFox data is used under CC BY 4.0 and the
free fair-use terms at <https://abuse.ch/terms-of-use/>; Feodo Tracker data is
offered under CC0 on a best-effort basis. The same credit appears in the web
client's footer and beneath any evidence panel that shows a feed match.

## Responsible use

SentinelX is a defensive analysis tool for education and for systems you own or
are explicitly authorised to monitor. It does not scan, probe, or act against
any system, and it must not be used to analyse data you are not permitted to
access. Demo data, where present, is synthetic and labelled as such. Findings
are decision support for an analyst, not a security guarantee.

## License

[MIT](LICENSE)
