# DATA_DICTIONARY.md
_Supported input schemas and feature definitions._

## Network flow dataset — UNSW-NB15 (primary; see DECISIONS.md for why)
- **Source:** UNSW Canberra Cyber Range Lab — research.unsw.edu.au/projects/unsw-nb15-dataset. Free for academic research use in perpetuity; cite the Moustafa & Slay papers listed on that page. Commercial use requires the authors' agreement — not relevant to this non-commercial portfolio project, but don't change that assumption without updating this note.
- **Files used:** `UNSW_NB15_training-set.csv` (175,341 rows) and `UNSW_NB15_testing-set.csv` (82,332 rows) — already pre-split by the dataset authors, so Phase 2 doesn't need to perform its own train/test split from the larger four-part CSV set.
- **Shape (verified against the downloaded files, 2026-11-16):** 45 columns per row — `id`, 42 features (3 categorical: `proto`, `service`, `state`; 39 numeric: flow duration, byte/packet counts, rate and inter-packet-time statistics, connection counts, TTL, window size, etc.) and the two target columns below. This is a reduced, partly renamed set of the 49 features described in the dataset's `NUSW-NB15_features.csv` (no IPs, ports, or timestamps). The exact column list lives in `backend/app/ml/schema.py`, taken from the file headers.
  - `id` — row number. Rows are ordered by class, so it tracks the label and is dropped before modelling.
  - `label` — binary, 0 = normal, 1 = attack
  - `attack_cat` — multi-class attack category: Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor, Shellcode, Worms; `Normal` for benign rows
- **Class imbalance (measured):** attacks are 68.1% of the training split and 55.1% of the testing split, so the two splits have different class balance. Categories are very uneven — in training, Generic 40,000 and Exploits 33,393 down to Shellcode 1,133 and Worms 130. Must be reported alongside precision/recall/F1/confusion matrix, never hidden or averaged away.
- **Known quirks (measured):** no missing values; `service` is `-` (unknown) for 54% of training rows; `proto` has 133 distinct values, most rare; the testing split contains `state` values absent from training (`ACC`, `CLO`); ignoring `id`, 67,601 training rows and 26,387 testing rows are exact duplicates of another row in the same split (kept as published); `is_ftp_login` is described as binary but ranges 0–4.
- **Preprocessing:** categorical features one-hot encoded, values seen fewer than 500 times in training grouped into one "infrequent" column, unseen values tolerated at inference; numeric features unscaled (tree-based baselines). Fitted on the training split only.
- **Novelty-detection path:** Isolation Forest is fitted on the feature columns of the training rows labelled normal only (56,000 of 175,341). `label` is used to select those rows and never as a training target; `attack_cat` is not used in training. It is evaluated on the full testing split, both classes. Measured: precision 0.820, recall 0.363, F1 0.504, false positive rate 0.098.
- **Not bundled into git:** the CSVs are fetched per the README's documented download step; only a small safe sample (a few hundred rows) is allowed to live in the repo for tests/demo-mode fixtures.

## Security log upload (CSV/JSON)
Final schema (confirmed 2026-11-16; implemented in `backend/app/ingestion/logs.py`, sample file `samples/demo_security_log.csv`, which is synthetic):
| Field | Type | Notes |
|---|---|---|
| `timestamp` | ISO 8601 string, required | must include a UTC offset or `Z`; stored as UTC |
| `event_type` | string, required | free-form, at most 64 characters, lower-cased; e.g. login_success, login_failure, access, config_change |
| `source_ip` | string, required | IPv4 or IPv6 address, stored in canonical form |
| `user` | string, optional | at most 256 characters |
| `status` | string, required | `success` or `fail`, case-insensitive |
| `asset_id` | string, optional | at most 256 characters |

- **Formats:** CSV with a header row (`text/csv`), or a JSON array of objects (`application/json`); UTF-8. Field names are exact and case-sensitive. JSON values must be strings; `null` or a blank value counts as absent.
- **Validation:** size (1 MiB, `MAX_REQUEST_BYTES`) and content type are checked before parsing. Then: required columns present, no repeated columns, every row valid. One invalid row rejects the whole file; the response lists the first 20 problems by row and field and counts the rest. Messages never repeat submitted values.
- **Other fields** are ignored and named in the response (first 20).
- **Rows** are numbered from 1 in file order, not counting the CSV header or blank lines.

## Phishing input
- Accepted input: pasted raw email text and/or header block, or a `.txt`/`.eml` upload. No automatic opening of links or execution of attachments, ever.
- Output: `label` (phishing / legitimate), `confidence`, and a `signals[]` list of the specific contributing evidence (e.g. mismatched sender domain, urgency language, suspicious link pattern) — never a bare verdict with no evidence attached.
- **Implemented (2026-11-26):** `POST /api/v1/phishing/classify` takes one email as `message/rfc822` or `text/plain` (headers optional, 1 MiB limit). Response fields: `label`, `phishing_probability`, `confidence` (probability of the predicted label; threshold 0.5), `signals[]` (`code`, `severity` info/suspicious, `description`, up to 3 `examples`), `model_terms` (`toward_phishing`, `toward_legitimate`: terms with signed weights, strongest first), `links_found`, `attachments_found`, `model` (name, training rows, held-out metrics). Parser in `backend/app/ingestion/email.py`, rules in `backend/app/detection/phishing_signals.py`, model in `backend/app/ml/phishing_model.py`.
- **Training corpus:** Nazario phishing corpus `phishing0-2.mbox` (CC BY 4.0) as phishing; SpamAssassin public corpus easy/hard ham (2002-2003, no stated licence, copyright stays with senders) as legitimate. Local only, in git-ignored `data/phishing/`. 5,920 messages after removing 3,298 exact-text duplicates (27.2% phishing), 29 unreadable. The model reads subject and visible body text only, never headers; the signals read headers, links and attachment names.

## Alert record
| Field | Notes |
|---|---|
| `id` | |
| `severity` | critical / high / medium / low — fixed enum, matches the one colour mapping used everywhere |
| `confidence` | 0–100 |
| `category` | e.g. data_exfiltration, brute_force, phishing |
| `source`, `asset` | |
| `evidence[]` | the specific fields/signals that produced this alert |
| `status` | open / acknowledged / false_positive / resolved |
| `created_at` | |
| `notes[]` | analyst-added |

**Implemented (2026-11-26)** in the SQLite table `alerts` (`backend/app/storage/alerts.py`): `id`, `created_at` (detection time, UTC), `occurred_at` (activity time from the input, nullable), `severity`, `confidence` (integer 0-100, checked by the database), `category` (`network_anomaly`, `brute_force`, `known_bad_source`, `suspicious_activity`, `phishing`), `source`, `asset` (nullable), `title`, `evidence` (JSON), `status` (default `open`; the four values above are enforced), and `demo` (0/1, set from the `demo` request flag). `notes[]` is not stored yet (investigation workflow). An evidence item is `{kind, name, description, value, examples[]}` with `kind` one of `model_score`, `rule_match`, `phishing_signal`, `model_term`, `caveat`. Severity and confidence rules are in the README ("Generate and list alerts") and DECISIONS.md.

## Investigation record
| Field | Notes |
|---|---|
| `incident_id` | |
| linked `alert_ids[]` | |
| `timeline[]` | `{event, timestamp}` entries |
| `evidence[]` | file references (pcap/log/process), with type + size |
| `affected_assets[]` | |
| `ai_analysis` | optional; must cite the evidence fields it used |
| `recommended_actions[]` | defensive only — never automatic blocking/exploitation/scanning |
