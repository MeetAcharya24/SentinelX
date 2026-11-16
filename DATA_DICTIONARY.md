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
- **Unsupervised path:** Isolation Forest trains on the feature columns only, with `label`/`attack_cat` held out and used solely for evaluation.
- **Not bundled into git:** the CSVs are fetched per the README's documented download step; only a small safe sample (a few hundred rows) is allowed to live in the repo for tests/demo-mode fixtures.

## Security log upload (CSV/JSON)
Draft required fields — confirm exact names in Phase 3 and publish the final schema + a sample file alongside the upload UI:
| Field | Type | Notes |
|---|---|---|
| `timestamp` | ISO 8601 string | must be parseable; reject file otherwise |
| `event_type` | string | e.g. login_success, login_failure, access, config_change |
| `source_ip` | string | IPv4/IPv6 |
| `user` | string (optional) | |
| `status` | string | success / fail |
| `asset_id` | string (optional) | |

Validation: required columns present, timestamp parseable, file size/type checked before any processing begins.

## Phishing input
- Accepted input: pasted raw email text and/or header block, or a `.txt`/`.eml` upload. No automatic opening of links or execution of attachments, ever.
- Output: `label` (phishing / legitimate), `confidence`, and a `signals[]` list of the specific contributing evidence (e.g. mismatched sender domain, urgency language, suspicious link pattern) — never a bare verdict with no evidence attached.

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
