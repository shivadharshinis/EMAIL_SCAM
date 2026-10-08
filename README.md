# Email Threat Detection, GeoLocation and Forensic Intelligence Platform

SIH106 student project for analyzing uploaded emails, estimating **probable
originating infrastructure** (not an attacker's exact location), scoring risk
with confidence, correlating cases, and generating forensic reports.

The application accepts an `.eml` upload or raw RFC 822 text and runs a hybrid
forensic pipeline: local rule-based threat detection, TF-IDF + Logistic
Regression classification, header and infrastructure intelligence, probable
origin analysis, campaign correlation, and final risk scoring. URLs are
extracted as evidence but are never visited.

## Tech stack

- Frontend: React, Vite, Tailwind CSS
- Backend: Python, FastAPI
- Database: MySQL SQLAlchemy connection helper is configured but not currently
  connected to analysis storage; there are no database migrations in this
  checkout
- Auth: optional JWT protection for case listing, analysis detail, model
  information, and report downloads

## Current setup

- React app shell with routes: Login, Register, Analyze, Cases, Investigation
- FastAPI endpoints include `GET /api/v1/health`, `POST /api/v1/analyze`,
  `GET /api/v1/analyses`, `GET /api/v1/analyses/{analysis_id}`,
  `GET /api/v1/model-info`, and `GET /api/v1/reports/{analysis_id}`
- SQLAlchemy engine/session helpers (no models or migrations yet)
- Modular email parser under `backend/app/engines/parser/`
- Separate rule-based threat detection under `backend/app/engines/detection/`
- Separate ML/NLP classifier under `backend/app/engines/ml/`
- Analysis records and campaign history are process-local and are cleared when
  the backend restarts; PostgreSQL persistence is not implemented

## Phase 1 analyze endpoint

`POST /api/v1/analyze` accepts either:

- multipart form data with a `file` field containing `.eml` or text email input
- JSON with a `raw_eml` string

The endpoint returns message identities, raw and selected headers, plain and
sanitized body content, extracted URL metadata, attachment metadata
(filename, MIME type, size, and SHA-256), threat indicators, ML output,
intelligence results, campaign correlation, and final risk. Email HTML is never
rendered or fetched, URLs are never visited, and attachments are never opened
or executed. Inputs are limited to 5 MB. Uploaded message content is held in
the process-local analysis result for investigation, but is not written to a
database or persisted across a backend restart.

## Required environment variables

Copy `.env.example` values into `backend/.env` (a starter file is already there):

| Variable | Purpose |
| --- | --- |
| `APP_NAME` | API title |
| `APP_ENV` | `development` / `production` |
| `API_V1_PREFIX` | API prefix (`/api/v1`) |
| `FRONTEND_ORIGIN` | Allowed CORS origin |
| `MYSQL_HOST` | MySQL host |
| `MYSQL_PORT` | MySQL port |
| `MYSQL_USER` | MySQL user |
| `MYSQL_PASSWORD` | MySQL password |
| `MYSQL_DATABASE` | Database name |

Optional frontend (`frontend/.env`):

- `VITE_API_BASE_URL` — defaults to `/api/v1` (Vite proxies `/api` to the backend)

MySQL does **not** need to be running for the health endpoint.

## Test Phase 1

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The parser tests cover normal, multipart, malformed, header, URL, attachment,
and sanitization cases. API tests cover JSON input, multipart upload, empty
input, and unsupported files.

## Phase 2 threat detection

The detector consumes parser facts and returns a `threat_detection` object with
a deterministic `rule_score` from 0 to 100, a summary, and explainable
indicators. Rules cover sender/reply/return-path mismatches, display-name
impersonation, punycode and IP-literal domains, explicit authentication
failures, transparent social-engineering phrases, URL characteristics, and
risky attachment extensions.

Missing SPF, DKIM, or DMARC information remains unknown and does not create an
indicator. URLs are analyzed without being visited, and attachments are only
represented by their existing metadata. This phase does **not** prove that an
email is malicious; it identifies suspicious indicators for review. The rule
score is not a final risk score and does not include ML or external
intelligence.

## Phase 3 ML/NLP classification

The ML engine is separate from the deterministic detection engine. It uses:

```text
Subject + plain-text body
    -> lowercase and whitespace normalization
    -> TfidfVectorizer
    -> LogisticRegression
    -> PHISHING or LEGITIMATE probability
```

The local dataset is documented at
`backend/app/engines/ml/data/README.md` and stored in
`backend/app/engines/ml/data/email_dataset.csv`. It contains 20 teaching/demo
examples: 10 legitimate and 10 phishing. No external dataset was downloaded.
The content is synthetic/anonymized and uses example domains.

This dataset is small, balanced by construction, and biased toward obvious
language. Its metrics are unstable and do not represent production
performance. The model must not be used as the sole basis for blocking or
investigating messages. No hyperparameter search or metric-driven tuning is
used.

Install the ML dependencies and train the model with:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.engines.ml.training.train
```

The training command uses a stratified `random_state=42` split and writes:

- `backend/app/engines/ml/artifacts/tfidf_vectorizer.joblib`
- `backend/app/engines/ml/artifacts/logistic_regression.joblib`
- `backend/app/engines/ml/artifacts/metrics.json`

Generated model binaries and metrics are ignored by Git. The training output
reports the actual dataset size, class distribution, accuracy, precision,
recall, F1-score, confusion matrix, and classification report.

The application reads evaluation metrics from the existing
`metrics.json` artifact through `GET /api/v1/model-info`; metric values are
not hardcoded. These are test-set results for the saved model, not a
production-performance guarantee.

Before training, or if artifacts are removed, the API returns an explicit
`ml_detection.available: false` response with an unavailable message. It never
fabricates a prediction. `ml_detection` remains separate from
`threat_detection.rule_score`; Phase 3 does not create a combined score.

## Phase 4 header and infrastructure intelligence

The API now returns `header_intelligence` with structured `Received` hops,
observed IPs, observed domains, and technical parsing anomalies. This analysis
is deterministic and makes no network requests. It does not prove malicious
activity and does not identify an attacker.

Optional passive RDAP enrichment is disabled by default. When explicitly
enabled, only extracted public IP/domain identifiers are sent to the provider;
the email body, full message, and attachments are never sent. RDAP failures
are returned as unavailable results and do not break email analysis.

Configure the optional service in `backend/.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PASSIVE_INTEL_ENABLED` | `false` | Enable passive RDAP lookups |
| `PASSIVE_INTEL_PROVIDER` | `rdap` | Passive provider name |
| `PASSIVE_INTEL_TIMEOUT_SECONDS` | `3` | Per-request timeout |
| `PASSIVE_INTEL_MAX_LOOKUPS` | `20` | Maximum identifiers per analysis |

RDAP registration and network metadata describe infrastructure and may be
incomplete or privacy-redacted. RDAP does not provide geographic data. To
enable optional IP geolocation, set `PASSIVE_INTEL_PROVIDER=ipapi.is`,
`PASSIVE_INTEL_ENABLED=true`, and provide `IPAPI_IS_API_KEY`. The resulting
country or coordinates describe observed infrastructure, not attacker
geolocation. The service does not visit URLs, perform DNS brute force, probe
IPs, connect to SMTP servers, execute attachments, or create a combined risk
score.

## Phase 6 campaign correlation and final risk

The API now returns campaign correlation and a separate deterministic final
risk result. Correlation compares normalized sender/Reply-To/Return-Path
domains, observed public IPs, URL domains, and normalized subjects against
previously analyzed records held in the process-local analysis index. Raw
email content and attachments are not used as campaign identifiers. No match
is fabricated when history is empty.

The final risk score is bounded from 0 to 100:

```text
45% rule score
35% ML phishing probability converted to 0-100
10% infrastructure signal score
10% campaign similarity score
```

Severity thresholds are LOW (0-24), MEDIUM (25-49), HIGH (50-74), and
CRITICAL (75-100). Rule score, ML probability, campaign similarity, and final
risk remain separately visible. This deterministic aggregation is evidence for
review, not certainty. Probable origin remains infrastructure geolocation and
does not identify an attacker's physical location.

## Phase 7 forensic reports

Each successful analysis receives an `analysis_id`. Use the stored analysis
endpoints to list available records or load an investigation:

```text
GET /api/v1/analyses
GET /api/v1/analyses/{analysis_id}
```

Download a structured ReportLab PDF:

```text
GET /api/v1/reports/{analysis_id}
```

The report includes the analysis ID and timestamp, email metadata and a short
body summary, observed URLs/domains/IPs, rule indicators, ML classification,
header and infrastructure intelligence, probable origin, campaign correlation,
and final risk evidence. It excludes the complete raw email body and does not
execute attachments or visit URLs. Analysis results are held in process-local
memory and are lost when the backend restarts; database persistence is not
currently wired into this project.

These endpoints are unauthenticated by default for local development. To
protect case listing, analysis detail, model information, and report downloads,
set `REPORT_AUTH_REQUIRED=true` and configure
`JWT_SECRET_KEY`, `JWT_ALGORITHM`, `JWT_EXPIRE_MINUTES`, `DEMO_USERNAME`, and
`DEMO_PASSWORD` in `backend/.env`. Obtain a demo token with
`POST /api/v1/auth/token`, then send it as a bearer token when downloading a
report. The analyze endpoint remains unauthenticated.

## How to start the backend

From the repo root:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check: http://127.0.0.1:8000/api/v1/health

## How to start the frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

App: http://localhost:5173
