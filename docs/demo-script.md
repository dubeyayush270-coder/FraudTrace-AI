# FraudTrace AI — 3–5 Minute Hackathon Demo Walkthrough

## Pre-Demo Preparation (Before Stepping Up)

1. Confirm the clean demo dataset is loaded (15 transactions across `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `SHARED_RECEIVER`, `HIGH_VOLUME_RECEIVER`, and `RAPID_FUND_MOVEMENT`).
2. Start both local servers from `D:\FraudTrace-AI`:
   ```powershell
   # Terminal 1 (Backend)
   backend\.venv\Scripts\uvicorn.exe --app-dir backend app.main:app --reload --host 127.0.0.1 --port 8000

   # Terminal 2 (Frontend)
   npm.cmd --prefix frontend run dev -- --host localhost --port 5173
   ```
3. Open **`http://localhost:5173/`** in full-screen browser view and verify **`Backend Connected`** (green) and **`SQLite Connected`** appear in the header/KPI bar.

---

## Walkthrough Script (~4 Minutes)

### Part 1 — Problem & Platform Overview (0:00 – 0:45)
- **Narration**: *"Traditional payment monitors inspect transactions one by one and produce opaque alerts. FraudTrace AI pairs explainable deterministic risk scoring with directed transaction graph intelligence so one suspicious payment can surface an entire network."*
- **Point to Header & KPI Strip**:
  - Highlight live **`Backend Connected`** (`/health`) and **`SQLite Connected`** (`/health/database`) telemetry.
  - Point out live metrics: **Total Transactions**, **High-Risk Transactions**, **Network Accounts**, and **Suspicious Patterns** — all computed directly from SQLite via FastAPI.

### Part 2 — Live Transaction Analysis & Duplicate Guard (0:45 – 1:45)
- **Action**: In the **Analyze Transaction** form:
  - Click **Auto Ref** (or type e.g. `LIVE-DEMO-901`).
  - Sender: `DEMO_RELAY_HUB`
  - Receiver: `DEMO_UNSEEN_EXCHANGE`
  - Amount: `1500.00`, Currency: `USD`
  - Click **Submit & Analyze Risk**.
- **Narration & Callout**:
  - Point to the **Latest Analysis Result** card: explain that `DEMO_RELAY_HUB` normally sends ~$50 utility payments, so sending `$1,500` to a brand-new recipient triggers `AMOUNT_ANOMALY` (`+30`, `HIGH`) and `NEW_RECIPIENT` (`+10`, `LOW`) for a deterministic score of `40 / 100` (`MEDIUM` / `UNDER_REVIEW`).
  - Click **Submit & Analyze Risk** again with the exact same reference (or enter an existing reference like `LIVE-DEMO-901`) to briefly show idempotent **`409 Conflict` Duplicate Reference** protection.

### Part 3 — Ledger Triage & Investigation Evidence (1:45 – 2:45)
- **Action**: In **Recent Transactions**, click the **`CRITICAL`** filter pill and select the `$650.00` transaction (`DEMO_BURST_SENDER → DEMO_MERCHANT_ESPRESSO`, score `80`).
- **Narration**:
  - Scroll/point to **Investigation Details**: show how FraudTrace AI explains *why* the payment scored `80 / 100` (`FLAGGED`, Case Priority `CRITICAL`) with three explicit evidence cards:
    1. `Transaction Velocity` (`MEDIUM`) — burst within 10 minutes
    2. `Amount Anomaly` (`HIGH`) — 6×+ above sender's baseline average
    3. `Repeated Recipient Activity` (`MEDIUM`) — repeated transfers to the same endpoint

### Part 4 — Fraud Network Graph & 1–2 Hop Investigation (2:45 – 4:00)
- **Action**: Switch attention to the **Transaction Network Graph** & **Account Network Inspector**:
  - Click the amber-ringed node **`DEMO_RELAY_HUB`** in the SVG graph (or click it under **Flagged Pattern Participants**).
  - Show how **Pattern Participants** (amber rings) stand out visually from standard accounts and how arrows depict `sender → receiver` flow with exact transaction references on edges.
  - In **Account Network Inspector**, walk through:
    - Incoming (`3`+) vs. Outgoing counts
    - **Connected Accounts (1–2 Hops)** showing 1-hop senders (`DEMO_ORIGIN_ALFA`, `DEMO_ORIGIN_BRAVO`, `DEMO_ORIGIN_CHARLIE`), 1-hop exit (`DEMO_EXIT_VAULT`), and 2-hop downstream (`DEMO_TREASURY_OUT`)
  - Below the graph, browse **Fraud Network Pattern Intelligence** cards:
    - **`HIGH_VOLUME_RECEIVER`** + **`SHARED_RECEIVER`** converging on `DEMO_RELAY_HUB`
    - **`RAPID_FUND_MOVEMENT`** catching funds passing from `DEMO_ORIGIN_* → DEMO_RELAY_HUB → DEMO_EXIT_VAULT → DEMO_TREASURY_OUT` within minutes
  - Optionally filter **Rapid Fund Movement**, and query a missing ID (e.g. `UNKNOWN_TEST`) to demonstrate graceful `404` handling.

### Part 5 — Responsible AI & Architecture Close (4:00 – 4:30)
- **Narration**: *"Notice our risk engine and network patterns explicitly report indicators as investigation leads—never automated guilt—with every claim backed by auditable transaction references stored across our FastAPI + SQLAlchemy + NetworkX architecture."*
