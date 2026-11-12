# FraudTrace AI — System Architecture

FraudTrace AI follows a **modular monolithic architecture** separating frontend presentation, FastAPI routing, deterministic fraud evaluation, graph intelligence, and relational SQLite persistence.

---

## High-Level Architecture Diagram

```mermaid
flowchart LR
    UI["React + Vite + Tailwind CSS v4 Dashboard"] -->|"REST JSON over HTTP"| API["FastAPI App (app/main.py)"]

    subgraph Backend["Backend Services (backend/app)"]
        API --> HR["Health Routes (/health, /health/database)"]
        API --> TR["Transaction Routes (/api/v1/transactions/*)"]
        API --> NR["Network Routes (/api/v1/network/*)"]
        API --> IR["Invoice Routes (/api/v1/invoices/*)"]
        API --> PR["PayPal Sandbox Routes (/api/v1/paypal/*)"]
        API --> AR["Assistant Routes (/api/v1/assistant/*)"]

        TR --> RE["Risk Engine (services/risk_engine.py)"]
        TR --> ML["Experimental ML Anomaly (services/ml_anomaly_detector.py)"]
        NR --> FG["Fraud Graph Service (services/fraud_graph.py)"]
        IR --> IE["Invoice Extractor (services/invoice_extractor.py)"]
        IR --> IA["Invoice Analyzer (services/invoice_analyzer.py)"]
        PR --> PC["PayPal Sandbox Client (services/paypal_client.py)"]
        PR --> RE
        AR --> AS["Assistant Service (services/assistant_service.py)"]
        AS --> AC["Context & Sanitizer (services/assistant_context.py)"]
        AS --> AP["AIProvider / GeminiProvider (services/ai_provider.py)"]
        AC --> ML
        AC --> FG

        RE --> DB["SQLAlchemy 2.x + SessionLocal (database.py)"]
        ML --> DB
        TR --> DB
        FG --> DB
        IA --> DB
        IR --> DB
        PR --> DB
        AC --> DB
        HR --> DB
    end

    DB -->|"PRAGMA foreign_keys=ON"| SQLITE["SQLite (backend/data/fraudtrace.db)"]
    SEED["Demo Seeder CLI (seed_demo_data.py)"] -->|"POST /api/v1/transactions/analyze"| TR
```

---

## Backend Modules (`backend/app/`)

1. **[`main.py`](../backend/app/main.py)**
   - Configures FastAPI lifespan startup (`init_db()`), CORS middleware (`http://localhost:5173`), health check endpoints (`/health`, `/health/database`), and API routers.
2. **[`database.py`](../backend/app/database.py)**
   - Anchors SQLite paths relative to `backend/` regardless of caller working directory.
   - Enables SQLite foreign-key enforcement (`PRAGMA foreign_keys=ON`) via a SQLAlchemy `Engine` connect listener.
   - Manages request-scoped sessions through `get_db()`.
3. **[`models.py`](../backend/app/models.py)**
   - `Transaction` (`Numeric(18, 2)` amount, unique `reference`, indexed `sender_id` and `receiver_id`, `risk_score`, `risk_level`, `investigation_status`)
   - `Investigation` (`transaction_id` FK with `CASCADE` delete, `status`, `summary`, `priority`)
   - `Evidence` (`investigation_id` FK with `CASCADE` delete, `evidence_type`, `description`, `severity`)
   - `Invoice` (`Numeric(18, 2)` `subtotal`/`tax`/`total_amount`, optional unique `submission_reference`, indexed `normalized_vendor_name` & `normalized_invoice_number`, `extraction_status`, `investigation_status`, serialized extracted/corrected field metadata)
   - `InvoiceFinding` (`invoice_id` FK with `CASCADE` delete, `finding_code`, `severity`, `explanation`, `supporting_values`)
   - `PayPalOrder` (`internal_reference` unique, `paypal_order_id` unique, `paypal_capture_id` unique nullable, `Numeric(18, 2)` `requested_amount`/`captured_amount`, `transaction_id` unique nullable FK to `transactions.id` with `SET NULL`; never stores OAuth secrets or tokens)
4. **[`schemas.py`](../backend/app/schemas.py)**
   - Pydantic v2 request/response contracts with positive amount checks, whitespace trimming, ISO 3-letter currency normalization, and invoice field/finding response schemas.
5. **Domain Services (`backend/app/services/`)**
   - **[`risk_engine.py`](../backend/app/services/risk_engine.py)**: Runs independent heuristic checks (`TRANSACTION_VELOCITY`, `AMOUNT_ANOMALY`, `NEW_RECIPIENT`, `REPEATED_RECIPIENT_ACTIVITY`), computes `0–100` score, assigns level and investigation status.
   - **[`ml_anomaly_detector.py`](../backend/app/services/ml_anomaly_detector.py)**: Fits a deterministic (`random_state=42`) `StandardScaler` + `IsolationForest` over causal prior transactions (`>= 10` required) to provide optional experimental `decision_function` scores and descriptive z-score feature deviations without modifying deterministic rules.
   - **[`fraud_graph.py`](../backend/app/services/fraud_graph.py)**: Builds a `networkx.MultiDiGraph` from persisted transactions and executes `detect_high_volume_receivers`, `detect_rapid_fund_movement`, `detect_shared_receivers`, and `get_account_connections`.
   - **[`invoice_extractor.py`](../backend/app/services/invoice_extractor.py)**: Validates bounded uploads (`<= 10 MB`), magic-byte signatures, PDF structure (`<= 5` pages, non-encrypted) via `PyMuPDF`, image dimensions/pixels via `Pillow`, probes external Tesseract availability honestly (`OCR_UNAVAILABLE` if absent), parses fields without inventing missing values, and tracks raw extracted values separately from optional user corrections.
   - **[`invoice_analyzer.py`](../backend/app/services/invoice_analyzer.py)**: Executes deterministic rules (`DUPLICATE_INVOICE`, `MISSING_CRITICAL_FIELDS`, `ARITHMETIC_MISMATCH` within `0.02` `Decimal` tolerance, `INVALID_DATE`, `DUE_BEFORE_INVOICE_DATE`, `FUTURE_INVOICE_DATE`, `EXTRACTION_QUALITY`) producing `NO_FINDINGS`, `NEEDS_REVIEW`, or `INCOMPLETE_EXTRACTION`.
6. **API Routes (`backend/app/routes/`)**
   - **[`transactions.py`](../backend/app/routes/transactions.py)**: Transaction ingestion/analysis (`409` on duplicate reference), paginated retrieval, and investigation detail queries.
   - **[`network.py`](../backend/app/routes/network.py)**: Network overview statistics, filtered pattern leads, and 1–2 hop account inspection.
   - **[`invoices.py`](../backend/app/routes/invoices.py)**: Multipart invoice upload investigation (`201`, `400`/`409`/`413`/`415`/`422`), newest-first paginated invoice history, and invoice investigation detail lookup.
   - **[`paypal_client.py`](../backend/app/services/paypal_client.py)**: PayPal Sandbox-only OAuth2 `client_credentials` token manager with thread-safe in-memory caching, early-expiry refresh, single `401` retry, HTTPS/Sandbox host enforcement, and Orders v2 create/get/capture methods.
   - **[`paypal.py`](../backend/app/routes/paypal.py)**: PayPal Sandbox `POST /api/v1/paypal/orders` and `POST /api/v1/paypal/orders/{order_id}/capture` endpoints with idempotent order creation, `APPROVED`-status verification, captured amount/currency parity checks, duplicate capture protection, and post-capture FraudTrace risk evaluation.
   - **[`ai_provider.py`](../backend/app/services/ai_provider.py)**: Provider-independent `AIProvider` protocol, environment-driven `AIAssistantConfig`, `synthetic_demo` data-classification privacy gate, sanitized timeout/quota/error hierarchy (`AITimeoutError` with `timeout_category`), official Google Gemini Developer API (`v1beta` `generateContent`) `GeminiProvider` implementation (default `gemini-3.8-flash`, overridable via `GEMINI_MODEL`, e.g., `gemini-3.7-flash` used in live testing), and optional `GroqProvider` (`openai/gpt-oss-20b`).
   - **[`assistant_context.py`](../backend/app/services/assistant_context.py)**: Read-only context builder for Transaction + ML, Network (1–2 hops + leads), Invoice (sanitized fields + findings + OCR limits), and Cross-Investigation scopes with PII/secret redaction, `ACCT_01`/`VENDOR_01` pseudonymization, and canonical `allowed_citations` registry.
   - **[`assistant_service.py`](../backend/app/services/assistant_service.py) & [`assistant.py`](../backend/app/routes/assistant.py)**: Stateless `GET /api/v1/assistant/status` and `POST /api/v1/assistant/chat` orchestration enforcing untrusted-data framing, prompt-injection/mutation refusal, strict server-side citation verification (stripping and disclosing fabricated citations), and output secret scrubbing.

---

## Core Data Flows

### 1. Transaction Analysis Flow (`POST /api/v1/transactions/analyze`)

```mermaid
sequenceDiagram
    participant Client as Dashboard / Seeder
    participant Route as transactions.py
    participant Engine as risk_engine.py
    participant DB as SQLite

    Client->>Route: POST /api/v1/transactions/analyze
    Route->>DB: Check reference uniqueness
    alt Duplicate reference
        Route-->>Client: HTTP 409 Conflict
    else Unique reference
        Route->>Engine: analyze_transaction_risk(sender, receiver, amount, ts)
        Engine->>DB: Query sender historical & rolling-window txns
        Engine-->>Route: Score, Risk Level, Investigation Status, Evidence list
        Route->>DB: Atomic commit (Transaction + Investigation + Evidence[])
        Route->>ML: evaluate_transaction_anomaly(txn) over causal prior history
        ML-->>Route: Optional MLAnomalyResponse (NORMAL / ANOMALY / UNAVAILABLE)
        Route-->>Client: HTTP 201 TransactionAnalyzeResponse (deterministic score preserved)
    end
```

### 2. Fraud Network Intelligence Flow (`GET /api/v1/network/*`)

1. Route opens read session via `get_db()` and calls `build_transaction_graph(db)`.
2. `Transaction` records are loaded in chronological order into an `nx.MultiDiGraph`, preserving multiple transfers between any `(sender_id, receiver_id)` pair.
3. Requested endpoint runs `detect_all_patterns(graph)` and/or `get_account_connections(graph, account_id, max_hops=2)`.
4. Results return strictly attributed account identifiers, transaction references, timestamps, and cautious lead explanations.

### 3. Invoice Investigation Flow (`POST /api/v1/invoices/analyze`)

1. Route verifies optional `submission_reference` uniqueness (`409` on conflict) and parses optional `corrections_json` (`400` on invalid/unknown keys).
2. `read_bounded_upload_sync` caps streaming payload at `10 MB` (`413`), and `extract_invoice_document` validates magic bytes (`415`), PDF structure (`<= 5` pages, non-encrypted via `PyMuPDF`), or image structure (`<= 10,000 px`, `<= 25,000,000` pixels via `Pillow`, `422`).
3. Text is read natively from PDFs or checked against dynamic host `tesseract` availability (reporting `OCR_UNAVAILABLE` cleanly when absent); parsed fields keep `extracted_value`, `corrected_value`, and `effective_value` separated without retaining uploaded file bytes.
4. `analyze_invoice` runs deterministic duplicate, missing-critical-field, `Decimal` arithmetic (`0.02` tolerance), date, and extraction-quality rules, committing `Invoice` and `InvoiceFinding[]` atomically without altering any transaction or ML records.

### 4. PayPal Sandbox Orders v2 Flow (`POST /api/v1/paypal/orders*`)

1. `PayPalSandboxClient` loads credentials strictly from environment variables (`PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_BASE_URL`), enforces Sandbox HTTPS URLs, and caches OAuth2 bearer tokens in memory only until `expires_in - 60s`.
2. `POST /api/v1/paypal/orders` validates amount/currency (`SUPPORTED_PAYPAL_CURRENCIES`, bounded `Decimal`), checks `internal_reference` idempotently against `paypal_orders` (returning `200` on exact match or `409` on parameter conflict), creates a `CAPTURE` order on PayPal with `PayPal-Request-Id`, validates Sandbox approval hosts, and persists `PayPalOrder` (`201`).
3. `POST /api/v1/paypal/orders/{order_id}/capture` short-circuits idempotently if already linked to a local `Transaction`, verifies via `GET /v2/checkout/orders/{order_id}` that PayPal reports `APPROVED` (or recovers cleanly if already `COMPLETED` on PayPal), runs `capture_order`, enforces `COMPLETED` capture status plus exact amount/currency parity, and evaluates the confirmed payment through `analyze_transaction_risk` without blocking or reversing completed captures.

### 5. AI Investigation Assistant Flow (`POST /api/v1/assistant/chat`)

1. Validates bounded stateless input (`message` 1–2000 chars, optional scope IDs, `extra="forbid"`) and screens direct prompt-injection, secret-exfiltration, SQL, or payment/DB-mutation attempts before external dispatch.
2. Enforces `AI_ENABLED=true`, `AI_DATA_CLASSIFICATION` (`synthetic_demo` by default unless `AI_ALLOW_EXTERNAL_NON_DEMO=true` is explicitly set), and `GEMINI_API_KEY` presence via `validate_external_ai_policy`.
3. `retrieve_investigation_context` queries read-only ORM models and existing `fraud_graph`/`ml_anomaly_detector` services, strips PII/secrets/raw invoice documents, pseudonymizes accounts/vendors (`ACCT_01`, `VENDOR_01`), and registers canonical `allowed_citations`.
4. Calls `AIProvider.generate_grounded_response` (`GeminiProvider` with structured JSON schema, `thinkingConfig.thinkingLevel="low"`, bounded timeout, and bounded `max_output_tokens`). If Gemini returns HTTP `503` **or raises `ReadTimeout`** (`timeout_category="read_timeout"`) and `GROQ_API_KEY` is configured, `ask_investigation_assistant` invokes `GroqProvider` (`openai/gpt-oss-20b` via `/openai/v1/chat/completions` with best-effort `json_schema`) once as a fallback without retrying Gemini and without falling back on `400`/`401`/`403`/`404`/`429`/`502`, other timeout categories (`ConnectTimeout`, `WriteTimeout`, `PoolTimeout`), transport errors, or invalid schema responses. Every returned `citation_id` is validated against `allowed_citations` (stripping and disclosing fabricated references), fallback limitation metadata is included when Groq runs, and responsible-use/privacy limitations are appended without mutating any database state.

---

## Frontend Architecture (`frontend/src/`)

- **[`services/api.ts`](../frontend/src/services/api.ts)**: Single centralized HTTP layer with `VITE_API_URL` environment configuration (`http://127.0.0.1:8000` fallback), multipart `FormData` upload handling, and unified error parsing.
- **[`types/api.ts`](../frontend/src/types/api.ts)**: Strict TypeScript interfaces aligned 1:1 with backend Pydantic models.
- **Dashboard Components (`frontend/src/components/`)**:
  - `HealthStatus.tsx` + `OverviewMetrics.tsx` — Live backend/DB connectivity and KPI cards.
  - `TransactionAnalyzeForm.tsx` + `RecentTransactionsTable.tsx` — Submission, immediate feedback, duplicate protection, and ledger filtering.
  - `InvestigationDetailsPanel.tsx` — Deep evidence inspection and linked network context.
  - `MLAnomalyCard.tsx` — Separate experimental IsolationForest panel showing `decision_function` score, non-probability disclaimers, and descriptive statistical deviations.
  - `NetworkGraphPanel.tsx` + `NetworkIntelligencePanel.tsx` — Custom SVG directed flow graph, 1–2 hop account inspector, and filterable network pattern cards.
  - `InvoiceInvestigationPanel.tsx` — **Invoices** workspace tab handling `PDF`/`PNG`/`JPG` upload validation, honest OCR availability status banners, separated extracted vs. user-corrected fields, severity-tagged findings, persisted invoice history, and StrictMode-safe sequence-coordinated invoice selection (`createInvoiceSelectionController`).
  - `InvestigationAssistantPanel.tsx` + `utils/safeMarkdown.tsx` + `utils/assistantHelpers.ts` — **AI Assistant** workspace tab (kept mounted across tab switches so in-memory conversation state persists without browser storage, with an explicit **Clear Conversation** control) providing scoped context selection (Transaction, Investigation, Invoice, Account), suggested questions, XSS-safe Markdown rendering, verified citation cards (`Inspect Record →` navigation to Transactions, Network, and Invoices), honest unavailable/error/retry states, and contextual "Ask AI" links from Transaction, Network, and Invoice panels.
