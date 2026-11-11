# FraudTrace AI

> **One suspicious payment can reveal an entire fraud network.**

FraudTrace AI is an explainable financial fraud intelligence platform that pairs deterministic, auditable transaction risk scoring with directed transaction graph analysis to surface multi-account fraud patterns and investigative evidence.

---

## Problem Statement

Traditional transaction monitoring evaluates each payment in isolation. Fraud operators exploit this blind spot by splitting activity across mule accounts, routing funds through shared collectors, and moving funds onward before static single-transaction thresholds trigger—while black-box risk scores leave investigators without clear evidence to act on.

## Solution & Key Features

FraudTrace AI combines transaction-level rule evaluation with network-wide relationship intelligence:

- **Explainable Transaction Risk Engine**: Evaluates every submitted payment across independent heuristic rules (`TRANSACTION_VELOCITY`, `AMOUNT_ANOMALY`, `NEW_RECIPIENT`, `REPEATED_RECIPIENT_ACTIVITY`), returning a capped `0–100` heuristic risk score, severity tier, investigation status, and structured `Evidence` findings.
- **Experimental ML Anomaly Detection**: Runs an unsupervised `scikit-learn` `IsolationForest` alongside (and strictly separate from) deterministic rules to surface statistical outlier leads (`decision_function` scores and descriptive z-score feature deviations) once at least 10 causal prior transactions exist.
- **Persistent Investigation Ledger**: Stores `Transaction`, `Investigation`, `Evidence`, `Invoice`, and `InvoiceFinding` records atomically in SQLite using SQLAlchemy 2.x with `Numeric(18, 2)` monetary precision and enforced foreign-key integrity (`PRAGMA foreign_keys=ON`).
- **Fraud Network Intelligence**: Builds a NetworkX directed multi-graph (`MultiDiGraph`) across transaction history to detect structural investigation leads (`HIGH_VOLUME_RECEIVER`, `RAPID_FUND_MOVEMENT`, `SHARED_RECEIVER`) and 1–2 hop account neighborhoods.
- **Invoice Investigation**: Validates `PDF` (up to `5` pages), `PNG`, and `JPG`/`JPEG` uploads (`10 MB` cap), extracts structured fields cleanly via `PyMuPDF` + `Pillow` (reporting `OCR_UNAVAILABLE` honestly when Tesseract is absent), preserves separated extracted vs. user-corrected fields, and executes deterministic duplicate, arithmetic, date, and completeness checks.
- **Dark-Navy Investigation Dashboard**: Interactive React + TypeScript + Tailwind CSS v4 console featuring live API/DB health telemetry, KPI summaries, real-time transaction submission and duplicate reference rejection (`409 Conflict`), filterable ledger triage, detailed evidence panels, an interactive directed SVG network graph, account lookup (`1–2` hop connections), and an **Invoices** investigation workspace tab.
- **Repeatable Demo Seeding**: Dedicated CLI seeder (`backend/seed_demo_data.py`) submitting timestamped demo flows through the public analysis endpoint without duplicate reference collisions.

---

## Architecture

FraudTrace AI uses a **modular monolithic** architecture with clear separation between the presentation layer, FastAPI routes, deterministic risk services, graph analytics, and SQLAlchemy persistence.

- **Frontend**: `frontend/` (React 19 + TypeScript + Vite 8 + Tailwind CSS v4)
- **Backend API & Services**: `backend/app/` (FastAPI + SQLAlchemy 2.x + NetworkX)
- **Database**: SQLite under `backend/data/fraudtrace.db`

For component diagrams, data flows, and entity relationships, see [`docs/architecture.md`](docs/architecture.md).

---

## Technology Stack

| Layer | Technologies |
| --- | --- |
| **Frontend** | React 19, TypeScript, Vite 8, Tailwind CSS v4, custom interactive SVG network graph |
| **Backend** | Python 3.13, FastAPI, Uvicorn, Pydantic v2, python-dotenv |
| **Database & ORM** | SQLAlchemy 2.x, SQLite (`Numeric(18, 2)` precision, `PRAGMA foreign_keys=ON`) |
| **ML Anomaly Layer (Experimental)** | `scikit-learn` (`IsolationForest`, `StandardScaler`), `numpy` |
| **Invoice Processing** | `PyMuPDF`, `Pillow`, conditional `pytesseract` (+ external Tesseract binary), `python-multipart` |
| **Network Intelligence** | NetworkX (`nx.MultiDiGraph`) |
| **Testing & Tooling** | Isolated Python verification suites, `httpx`, `tsc`, `oxlint` |

---

## How the Risk Engine Works

Implemented in [`backend/app/services/risk_engine.py`](backend/app/services/risk_engine.py), each submitted transaction starts at `0` risk points and is evaluated independently against four deterministic rules (capped at `100`):

| Rule / Evidence Type | Condition | Points | Severity |
| --- | --- | --- | --- |
| `TRANSACTION_VELOCITY` | Sender has **3 or more** prior transactions within a rolling **10-minute** window | `+25` | `MEDIUM` |
| `AMOUNT_ANOMALY` | Amount is **≥ 5×** the sender's historical average in the **same currency** (minimum **3** prior transactions required) | `+30` | `HIGH` |
| `NEW_RECIPIENT` | First recorded transaction from `sender_id` to `receiver_id` (informational indicator) | `+10` | `LOW` |
| `REPEATED_RECIPIENT_ACTIVITY` | Sender sent **3 or more** transactions to the **same recipient** within **10 minutes** | `+25` | `MEDIUM` |

**Score Tiers & Investigation Status Mapping:**
- `0–24`: `LOW` → `CLEARED` (Investigation `CLOSED`)
- `25–49`: `MEDIUM` → `UNDER_REVIEW` (Investigation `OPEN`)
- `50–74`: `HIGH` → `FLAGGED` (Investigation `OPEN`)
- `75–100`: `CRITICAL` → `FLAGGED` (Investigation `OPEN`)

*Note: Scores reflect deterministic rule accumulation, not calibrated fraud probabilities.*

---

## Experimental ML Anomaly Detection

Implemented in [`backend/app/services/ml_anomaly_detector.py`](backend/app/services/ml_anomaly_detector.py), an unsupervised `IsolationForest` (`random_state=42`) evaluates behavioral unusualness independently of the deterministic rule engine:

- **Strict Score Isolation**: ML outputs are returned in optional `ml_anomaly` metadata on `POST /api/v1/transactions/analyze` and `GET /api/v1/transactions/{transaction_id}`. They never alter `risk_score`, `risk_level`, or `investigation_status`.
- **Leakage-Free Causal Features**: Builds 8 derived numerical features (`amount`, `log_amount`, `sender_tx_count`, `receiver_tx_count`, `sender_velocity_10m`, `is_new_recipient`, `sender_historical_avg`, `amount_to_avg_ratio`) without raw account identifiers or investigation outcomes. Each training row's features use only preceding rows, and the evaluated transaction plus any future rows are excluded from training.
- **Minimum Sample Guard**: Requires at least **10** valid prior historical transactions (and non-zero feature variance); otherwise returns `status="UNAVAILABLE"` cleanly without disrupting API calls.
- **Score Interpretation**: Uses `IsolationForest.decision_function` directly — **lower values indicate more unusual behavior**, with values below `0.0` flagged as `ANOMALY`. Feature deviations report descriptive statistical z-score distance from the training baseline (not SHAP values, causal attributions, or fraud probabilities).

---

## Fraud Network Intelligence

Implemented in [`backend/app/services/fraud_graph.py`](backend/app/services/fraud_graph.py), persisted transactions are loaded into a `networkx.MultiDiGraph` where each account is a node and each transaction is preserved as a directed edge (`sender_id → receiver_id`) with `transaction_id`, `reference`, `amount`, `currency`, and UTC `timestamp` attributes.

**Detectors Implemented:**
1. **`HIGH_VOLUME_RECEIVER`**: Accounts receiving funds from **≥ 3 distinct senders** within a configurable **60-minute** sliding window.
2. **`RAPID_FUND_MOVEMENT`**: Accounts receiving inbound funds and sending outbound transfers within **30 minutes**, attributing both incoming and outgoing transaction references.
3. **`SHARED_RECEIVER`**: Accounts receiving transactions from **≥ 2 distinct connected senders**, reporting distinct sender count and supporting references.
4. **`ACCOUNT_CONNECTIONS`**: 1–2 hop undirected neighborhood traversal classifying links as `incoming`, `outgoing`, `bidirectional`, or `indirect_2_hop`.

---

## Invoice Investigation

Implemented in [`backend/app/services/invoice_extractor.py`](backend/app/services/invoice_extractor.py) and [`backend/app/services/invoice_analyzer.py`](backend/app/services/invoice_analyzer.py), this module inspects uploaded vendor invoices (`PDF` up to `5` pages, `PNG`, `JPG`/`JPEG`, `10 MB` cap) without permanently storing raw document files or inventing missing numbers:

- **Upload Validation & Security Controls**: Streams uploads bounded to `10 MB` (`413`), verifies magic-byte signatures (`415`), blocks encrypted/malformed/0-page/`> 5`-page PDFs via `PyMuPDF` (`422`), and enforces Pillow structural verification plus pixel/dimension limits (`10,000 px` max dimension, `25,000,000` pixels) to guard against image decompression bombs (`422`).
- **Honest OCR Availability Reporting**: Extracts selectable PDF text natively with `PyMuPDF` and checks dynamically whether a system `tesseract` executable is available before attempting OCR. When Tesseract is absent (as on the current Windows host), image uploads and scanned/image-only PDFs report `ocr_available=false`, `extraction_status="OCR_UNAVAILABLE"`, and `investigation_status="INCOMPLETE_EXTRACTION"` rather than returning a false clean pass.
- **Separated Extracted vs. User Corrections**: Stores `extracted_value`, optional `corrected_value`, `effective_value`, `extraction_status`, and confidence metadata side-by-side without overwriting raw extraction results.

**Deterministic Invoice Rules:**
1. **`DUPLICATE_INVOICE`** (`HIGH`): Matches normalized `vendor_name` and normalized `invoice_number` against prior persisted invoices (returns `409 Conflict` when `reject_duplicates=true`).
2. **`MISSING_CRITICAL_FIELDS`** (`MEDIUM` / `HIGH`): Flags missing `vendor_name`, `invoice_number`, `invoice_date`, or `total_amount` without fabricating substitutes.
3. **`ARITHMETIC_MISMATCH`** (`HIGH`): When `subtotal`, `tax`, and `total_amount` are all present, verifies `subtotal + tax ≈ total_amount` using exact `Decimal` arithmetic within a `0.02` rounding tolerance.
4. **Date Consistency Rules**: Flags unparseable calendar dates (`INVALID_DATE`), `due_date < invoice_date` (`DUE_BEFORE_INVOICE_DATE`, `HIGH`), and future-dated invoices (`FUTURE_INVOICE_DATE`, `MEDIUM` warning noting pre-billing must be verified and does not establish fraud).
5. **`EXTRACTION_QUALITY`** (`LOW` / `MEDIUM` / `HIGH`): Records `OCR_UNAVAILABLE`, `UNREADABLE`, or `PARTIAL_EXTRACTION` status transparently.

**Investigation Outcome Mapping:** `NO_FINDINGS`, `NEEDS_REVIEW`, or `INCOMPLETE_EXTRACTION`.

---

## API Overview

Base URL (local default): `http://127.0.0.1:8000` (interactive OpenAPI docs at `/docs`)

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Basic backend liveness check (`{"status": "ok"}`) |
| `GET` | `/health/database` | Active SQLite connectivity check (`200 OK` or `503 Service Unavailable`) |
| `POST` | `/api/v1/transactions/analyze` | Evaluate and persist transaction, investigation, and evidence (`201`, or `409` on duplicate reference) |
| `GET` | `/api/v1/transactions` | Paginated recent transactions ordered by timestamp descending (`limit`, `offset`) |
| `GET` | `/api/v1/transactions/{transaction_id}` | Full transaction record with linked investigations and evidence (`404` if missing) |
| `GET` | `/api/v1/network/overview` | Node/edge counts, connected components, pattern counts, and participant identifiers |
| `GET` | `/api/v1/network/patterns` | Paginated suspicious pattern leads (`limit`, `offset`, optional `pattern_type` filter) |
| `GET` | `/api/v1/network/accounts/{account_id}` | Account incoming/outgoing counts, 1–2 hop connections, patterns, and transaction references (`404` if missing) |
| `POST` | `/api/v1/invoices/analyze` | Validate multipart invoice upload (`PDF`/`PNG`/`JPG`), extract fields, run deterministic rules, and persist (`201`, or `409`/`413`/`415`/`422`) |
| `GET` | `/api/v1/invoices` | Paginated persisted invoice investigation summaries newest-first (`limit`, `offset`) |
| `GET` | `/api/v1/invoices/{invoice_id}` | Full invoice metadata, extracted vs. corrected field breakdown, and deterministic findings (`404` if missing) |

---

## Installation & Startup Instructions

### Prerequisites
- Python **3.13** (virtual environment configured at `backend/.venv`)
- Node.js & npm (for `frontend/`)

### 1. Environment Configuration (Optional Overrides)
Copy the template files only if you want custom values:
- Backend template: [`backend/.env.example`](backend/.env.example) → `backend/.env` (`DATABASE_URL=sqlite:///./data/fraudtrace.db`)
- Frontend template: [`frontend/.env.example`](frontend/.env.example) → `frontend/.env` (`VITE_API_URL=http://127.0.0.1:8000`)

### 2. Install Dependencies
```powershell
# Backend (inside D:\FraudTrace-AI)
backend\.venv\Scripts\pip.exe install -r backend\requirements.txt

# Frontend
npm.cmd --prefix frontend install
```

### 3. Start Backend & Frontend (Two Terminals)
From `D:\FraudTrace-AI`:

```powershell
# Terminal 1 — FastAPI Backend (http://127.0.0.1:8000)
backend\.venv\Scripts\uvicorn.exe --app-dir backend app.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
# Terminal 2 — React Frontend (http://localhost:5173)
npm.cmd --prefix frontend run dev -- --host localhost --port 5173
```

Open **`http://localhost:5173/`** in your browser.

*(Important: backend CORS currently allows `http://localhost:5173`; open `localhost:5173` rather than `127.0.0.1:5173`.)*

---

## Demo Data Instructions

With the backend running on `http://127.0.0.1:8000`, populate timestamped demo scenarios via the API:

```powershell
backend\.venv\Scripts\python.exe backend\seed_demo_data.py
```

A single run inserts **15 transactions** tagged `DEMO-<UTC_TIMESTAMP>-<HEX>-01..15` demonstrating:
- **LOW** (`0` / `10`), **MEDIUM** (`40` — Amount Anomaly + New Recipient), **HIGH** (`50` — Velocity + Repeated Recipient), and **CRITICAL** (`80` — Velocity + Repeated Recipient + Amount Anomaly) risk scores.
- **High-Volume Receiver** & **Shared Receiver** hubs (`DEMO_RELAY_HUB`, `DEMO_EXIT_VAULT`).
- **Rapid Fund Movement** multi-hop chains (`DEMO_ORIGIN_* → DEMO_RELAY_HUB → DEMO_EXIT_VAULT → DEMO_TREASURY_OUT`).

### Safe Procedure to Reset & Re-Seed the Demo Database

Never delete `backend/data/fraudtrace.db` without backing it up first, and stop Uvicorn before moving database files:

```powershell
# 1. Stop Uvicorn (Ctrl+C in the backend terminal)
# 2. Back up the current database (timestamped backup; ignored by Git)
Copy-Item backend\data\fraudtrace.db "backend\data\fraudtrace.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss').db.bak"

# 3. Remove the active SQLite file after verifying the backup exists
Remove-Item backend\data\fraudtrace.db

# 4. Restart Uvicorn (automatically initializes a clean schema) and seed once
backend\.venv\Scripts\uvicorn.exe --app-dir backend app.main:app --reload --host 127.0.0.1 --port 8000
backend\.venv\Scripts\python.exe backend\seed_demo_data.py
```

---

## Testing Instructions

All backend verification scripts run against **isolated temporary SQLite databases** and leave `backend/data/fraudtrace.db` untouched.

```powershell
# Backend test suites (from D:\FraudTrace-AI)
backend\.venv\Scripts\python.exe backend\test_database.py
backend\.venv\Scripts\python.exe -u backend\test_risk_engine_and_api.py
backend\.venv\Scripts\python.exe -u backend\test_fraud_network.py
backend\.venv\Scripts\python.exe -u backend\test_ml_anomaly.py
backend\.venv\Scripts\python.exe -u backend\test_invoice_investigation.py

# Frontend TypeScript check, production build & linter
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run lint
```

---

## Current Limitations

- **Experimental Unsupervised ML Only**: The `IsolationForest` anomaly check is trained on small local database history without fraud labels, hyperparameter cross-validation, or FX normalization across currencies. It provides exploratory outlier leads only and has **not** been statistically validated for production accuracy. LLM narrative generation and PayPal Sandbox webhook integration remain out of scope for this milestone.
- **External Tesseract Prerequisite for Scanned Invoices**: Text-based PDFs extract natively via `PyMuPDF`, whereas `PNG`/`JPG` images and scanned image-only PDFs require an external host `tesseract` executable (`Tesseract-OCR`) for OCR. On systems without Tesseract installed (including the current Windows environment), the backend reports `OCR_UNAVAILABLE` and `INCOMPLETE_EXTRACTION` honestly instead of performing OCR; reviewers can inspect files manually or supply explicit field corrections cleanly.
- **On-Demand In-Memory Graph**: NetworkX graphs are rebuilt per `/api/v1/network/*` request from SQLite transactions; suitable for hackathon/prototype volumes rather than million-edge streaming graphs.
- **Local Single-Origin Configuration**: CORS is configured strictly for `http://localhost:5173`, with no user authentication or role-based access control enabled yet.
- **Dashboard Window Limits**: The High-Risk KPI counts `HIGH`/`CRITICAL` transactions across the latest `100` fetched records, and the SVG graph displays up to `24` prioritized nodes in `All Nodes` mode (use `Selected Focus` to isolate individual neighborhoods).

---

## Responsible-Use Disclaimer

FraudTrace AI is an **investigative decision-support prototype**. Heuristic risk scores, triggered rules, and structural network patterns serve exclusively as **investigation leads** for qualified analysts. Model outputs and graph anomalies **do not establish fraud, money laundering, or criminal guilt**, and should never be used as sole grounds for adverse action against any individual or organization.
