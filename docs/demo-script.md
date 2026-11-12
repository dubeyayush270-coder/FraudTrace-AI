# FraudTrace AI — End-to-End Platform Demo Walkthrough

## Pre-Demo Preparation (Before Stepping Up)

1. Confirm the clean demo dataset is loaded in SQLite (or follow the safe backup/seed steps in [`README.md`](../README.md) using `backend/seed_demo_data.py`).
2. Start both local servers from `D:\FraudTrace-AI`:
   ```powershell
   # Terminal 1 (Backend)
   backend\.venv\Scripts\uvicorn.exe --app-dir backend app.main:app --reload --host 127.0.0.1 --port 8000

   # Terminal 2 (Frontend)
   npm.cmd --prefix frontend run dev -- --host localhost --port 5173
   ```
3. Open **`http://localhost:5173/`** in the browser (`Full Workspace` or individual workspace tabs: `Transactions & Risk`, `Network & Graph`, `Invoices`, `AI Assistant`).

---

## Walkthrough Script (~5–7 Minutes)

### 1. Dashboard & System Health (`Full Workspace` Header & KPI Bar)
- **Verify live telemetry**: Point out **`Backend Connected`** (`/health`) and **`SQLite Connected`** (`/health/database`) in the top status strip alongside **Total Transactions**, **High-Risk Transactions**, **Network Accounts**, and **Suspicious Patterns**.
- **Narration**: *"FraudTrace AI pairs deterministic, explainable transaction risk scoring with directed transaction graph intelligence, invoice verification, Sandbox payment integration, and an evidence-grounded AI explanation layer."*

### 2. Explainable Transaction Risk Analysis (`Transactions & Risk`)
- **Action**: In the transaction submission form:
  - Click **Auto Ref** (or enter e.g. `LIVE-DEMO-901`).
  - Sender: `DEMO_RELAY_HUB`, Receiver: `DEMO_UNSEEN_EXCHANGE`, Amount: `1500.00`, Currency: `USD`.
  - Click **Submit & Analyze Risk** (`POST /api/v1/transactions/analyze`).
- **Narration & Duplicate Protection**:
  - Show how `AMOUNT_ANOMALY` (`+30`, `HIGH`) and `NEW_RECIPIENT` (`+10`, `LOW`) produce a deterministic score of `40 / 100` (`MEDIUM` / `UNDER_REVIEW`) with auditable `Evidence` findings—not a black-box score or guilt determination.
  - Re-submit the same reference to show **`409 Conflict`** duplicate reference rejection.
  - In **Recent Transactions**, filter by **`CRITICAL`** and select a high-score burst transaction to open **Investigation Details** and review each triggered rule.

### 3. Fraud Network Intelligence (`Network & Graph`)
- **Action**: Switch to **`Network & Graph`** (or inspect the network section below).
  - Select an amber-ringed node such as **`DEMO_RELAY_HUB`** in **Transaction Network Graph** or **Flagged Pattern Participants**.
  - Review **Account Network Inspector** (`1–2` hop connected accounts and transaction references) and filter **Suspicious Pattern** cards (`HIGH_VOLUME_RECEIVER`, `SHARED_RECEIVER`, `RAPID_FUND_MOVEMENT`).
  - Optionally query an unknown account ID to demonstrate clean **`404`** handling.
- **Narration**: *"Graph patterns highlight structural movement indicators as investigation leads backed by exact timestamps and transaction references."*

### 4. Experimental ML Anomaly Detection (`Investigation Details` → `ML Anomaly Intelligence`)
- **Action**: With a transaction selected that has `>= 10` causal prior transactions, point to the **`ML Anomaly Intelligence` (`Experimental`)** card.
- **Narration & Guardrails**:
  - Show the unsupervised `IsolationForest` `decision_function` score (`Behavioral Outlier`, `No Outlier Flagged`, or `Unavailable` when causal baseline history has `< 10` rows).
  - Emphasize explicitly: ML anomaly outputs **never alter** deterministic `risk_score`, are **exploratory outlier distances (not calibrated fraud probabilities or confirmed guilt)**, and are strictly isolated from target/future leakage.

### 5. Invoice Investigation & Honest OCR Limitations (`Invoices`)
- **Action**: Open the **`Invoices`** tab.
  - Browse **Invoice Investigation History** and click a persisted record to load **Invoice Investigation Details**.
  - Demonstrate uploading a sample text-based `PDF` (or `PNG`/`JPG` with optional reviewer overrides under `Add Optional Reviewer Corrections / Duplicate Policy`) and click **Analyze Invoice** (`POST /api/v1/invoices/analyze`).
- **Honest OCR & Extraction Callout**:
  - Highlight that native PDF text extracts directly via `PyMuPDF`, whereas `PNG`/`JPG` images and scanned PDFs depend on an external system `tesseract` executable.
  - When Tesseract is unavailable on the host, the UI honestly reports `OCR_UNAVAILABLE` and `INCOMPLETE_EXTRACTION` rather than faking extraction or returning a false clean pass.
  - Point out that `extracted_value` and manual `corrected_value` stay separated side-by-side alongside deterministic findings (`DUPLICATE_INVOICE`, `MISSING_CRITICAL_FIELDS`, `ARITHMETIC_MISMATCH`, date checks).

### 6. PayPal Sandbox Order Creation & Capture Overview (`http://127.0.0.1:8000/docs`)
- **Action**: Open FastAPI Swagger UI at **`http://127.0.0.1:8000/docs`** (or show offline verification tests) to point to:
  - `POST /api/v1/paypal/orders` (Sandbox `CAPTURE` order creation with `internal_reference` idempotency)
  - `POST /api/v1/paypal/orders/{order_id}/capture` (verifies PayPal `APPROVED` status, enforces captured amount/currency parity, prevents duplicate capture transactions, and evaluates captured payments via `analyze_transaction_risk`)
- **Important Demo Boundaries**:
  - **Do not trigger a live PayPal capture during the walkthrough**, and do not present PayPal production payments as enabled. FraudTrace AI strictly targets PayPal **Sandbox** (`api-m.sandbox.paypal.com`), keeps OAuth credentials/tokens server-side only, and does not include frontend PayPal checkout buttons or webhook verification in this prototype.

### 7. AI Investigation Assistant (`AI Assistant`)
- **Action**: Click **`Ask AI about Txn #...`** (from Transaction Details), **`Ask AI about Invoice #...`** (from Invoice Details), or open the **`AI Assistant`** tab directly.
- **Demonstrate Key Behaviors**:
  - Explain **Privacy & Grounding Controls**: queries retrieve scoped, **sanitized synthetic/demo context** (`AI_DATA_CLASSIFICATION=synthetic_demo`); PII/secrets/raw invoice documents are stripped and accounts/vendors are pseudonymized (`ACCT_01`, `VENDOR_01`) before any outbound LLM call. If `AI_ENABLED=false`, the UI displays an honest **External AI Provider Not Ready** banner without simulating answers.
  - Ask a question (or click a **Suggested Question**) and review the structured markdown answer (`Observed Evidence`, `Analytical Interpretation`, `Recommended Next Steps`), **Limitations & Uncertainty Disclosures**, and **Verified Evidence Citations**.
  - Click **`Inspect Record →`** on `TXN`, `ACCT`, or `INVOICE` citations to jump directly to the corresponding dashboard tab, then click back to **`AI Assistant`** to confirm the conversation thread stays intact across tab navigation.
  - Click **`Clear Conversation`** in the Assistant header to reset the in-memory thread cleanly.

### 8. Gemini Primary & Groq Fallback Behavior
- **Explain Provider Resilience**:
  - **Primary Provider**: Google Gemini (`AI_PROVIDER=gemini`, default `gemini-3.8-flash` or tested override such as `gemini-3.7-flash` with `thinkingLevel="low"`, structured JSON schema, and 30s timeout).
  - **Optional Single Fallback**: If `GROQ_API_KEY` is configured and Gemini returns **HTTP `503`** or **`ReadTimeout`**, the backend invokes Groq (`openai/gpt-oss-20b`) once without retrying Gemini and discloses fallback usage in `limitations` and the response metadata badge (`groq/openai/gpt-oss-20b`).
  - **Fail-Closed Guards**: Authentication/client/rate-limit errors (`400`/`401`/`403`/`404`/`429`), other timeout types (`ConnectTimeout`/`WriteTimeout`/`PoolTimeout`), schema violations, and prompt-injection/mutation attempts never trigger silent retries or bypass safety boundaries.

### 9. Responsible-Use Closing Summary
- **Narration**: *"Every component in FraudTrace AI—deterministic transaction rules, `IsolationForest` outlier checks, NetworkX flow patterns, invoice checks, and the stateless AI assistant—treats outputs strictly as auditable investigation leads for human review. Scores are not fraud probabilities, AI explanations never establish criminal guilt or mutate records/payments, and the system degrades transparently when optional capabilities such as Tesseract OCR or external LLM providers are unavailable."*
