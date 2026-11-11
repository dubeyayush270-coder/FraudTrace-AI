"""
FraudTrace AI — Repeatable Demo Data Seeder
==========================================
Submits realistic demo transactions through the existing FastAPI endpoint
(`POST /api/v1/transactions/analyze`) to populate:
- Baseline low-risk transactions
- SHARED_RECEIVER and HIGH_VOLUME_RECEIVER patterns
- RAPID_FUND_MOVEMENT multi-hop chains
- Transaction velocity & amount anomaly alerts

Usage:
    backend/.venv/Scripts/python.exe backend/seed_demo_data.py
    backend/.venv/Scripts/python.exe backend/seed_demo_data.py --api-url http://127.0.0.1:8000
"""

import argparse
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import httpx


def build_demo_transactions(run_tag: str, now: datetime) -> list[dict[str, str]]:
    """
    Constructs timestamped demo payloads with unique references per run.
    All references (`DEMO-...`) and accounts (`DEMO_...`) are explicitly labeled.
    """
    specs = [
        # 1. Baseline history for DEMO_RELAY_HUB (low-risk recurring vendor payments)
        ("DEMO_RELAY_HUB", "DEMO_UTILITY_CO", "45.00", "USD", now - timedelta(days=4)),
        ("DEMO_RELAY_HUB", "DEMO_UTILITY_CO", "50.00", "USD", now - timedelta(days=3)),
        ("DEMO_RELAY_HUB", "DEMO_UTILITY_CO", "55.00", "USD", now - timedelta(days=2)),
        ("DEMO_RELAY_HUB", "DEMO_UTILITY_CO", "52.00", "USD", now - timedelta(minutes=22)),

        # 2. High-Volume + Shared Receiver cluster into DEMO_RELAY_HUB
        ("DEMO_ORIGIN_ALFA", "DEMO_RELAY_HUB", "320.00", "USD", now - timedelta(minutes=14)),
        ("DEMO_ORIGIN_BRAVO", "DEMO_RELAY_HUB", "410.00", "USD", now - timedelta(minutes=10)),
        ("DEMO_ORIGIN_CHARLIE", "DEMO_RELAY_HUB", "385.00", "USD", now - timedelta(minutes=6)),

        # 3. Rapid onward movement + Amount Anomaly out of DEMO_RELAY_HUB -> DEMO_EXIT_VAULT
        ("DEMO_RELAY_HUB", "DEMO_EXIT_VAULT", "1100.00", "USD", now - timedelta(minutes=4)),

        # 4. Secondary feed + 2-hop exit chain
        ("DEMO_COLLECTOR_DELTA", "DEMO_EXIT_VAULT", "620.00", "USD", now - timedelta(minutes=3)),
        ("DEMO_EXIT_VAULT", "DEMO_TREASURY_OUT", "1650.00", "USD", now - timedelta(minutes=2)),

        # 5. Velocity + repeated recipient + amount anomaly burst (HIGH & CRITICAL transactions)
        ("DEMO_BURST_SENDER", "DEMO_MERCHANT_ESPRESSO", "95.00", "USD", now - timedelta(minutes=6)),
        ("DEMO_BURST_SENDER", "DEMO_MERCHANT_ESPRESSO", "98.00", "USD", now - timedelta(minutes=4)),
        ("DEMO_BURST_SENDER", "DEMO_MERCHANT_ESPRESSO", "96.00", "USD", now - timedelta(minutes=2)),
        ("DEMO_BURST_SENDER", "DEMO_MERCHANT_ESPRESSO", "97.00", "USD", now - timedelta(minutes=1)),
        ("DEMO_BURST_SENDER", "DEMO_MERCHANT_ESPRESSO", "650.00", "USD", now - timedelta(seconds=30)),
    ]

    payloads: list[dict[str, str]] = []
    for idx, (sender, receiver, amount, currency, ts) in enumerate(specs, start=1):
        payloads.append(
            {
                "reference": f"DEMO-{run_tag}-{idx:02d}",
                "sender_id": sender,
                "receiver_id": receiver,
                "amount": amount,
                "currency": currency,
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
            }
        )
    return payloads


def seed_demo_data(api_url: str) -> int:
    base_url = api_url.rstrip("/")
    now = datetime.now(timezone.utc)
    run_tag = f"{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
    payloads = build_demo_transactions(run_tag, now)

    print(f"FraudTrace AI Demo Seeder | Target API: {base_url}")
    print(f"Run Tag: DEMO-{run_tag} ({len(payloads)} demo transactions)\n")

    try:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            health = client.get("/health")
            if health.status_code != 200 or health.json().get("status") != "ok":
                print(
                    f"Error: Backend health check failed ({health.status_code}). "
                    "Start FastAPI before running demo seed.",
                    file=sys.stderr,
                )
                return 1

            for item in payloads:
                resp = client.post("/api/v1/transactions/analyze", json=item)
                if resp.status_code != 201:
                    print(
                        f"Failed {item['reference']}: HTTP {resp.status_code} -> {resp.text}",
                        file=sys.stderr,
                    )
                    return 1
                data = resp.json()
                print(
                    f"  [+] {item['reference']} | "
                    f"{item['sender_id']} -> {item['receiver_id']} | "
                    f"${item['amount']} {item['currency']} | "
                    f"Score={data['risk_score']} ({data['risk_level']}, {data['investigation_status']})"
                )

            overview = client.get("/api/v1/network/overview")
            if overview.status_code == 200:
                ov = overview.json()
                print("\nUpdated Network Overview:")
                print(f"  - Total accounts: {ov['total_accounts']}")
                print(f"  - Total transactions: {ov['total_transactions']}")
                print(f"  - Connected components: {ov['connected_components']}")
                print(f"  - Suspicious patterns detected: {ov['suspicious_patterns_detected']}")
                print(f"  - Pattern summary: {ov['patterns_summary']}")

        print("\nDemo data seeding completed cleanly.")
        return 0

    except httpx.RequestError as exc:
        print(
            f"Connection error reaching {base_url}: {exc}\n"
            "Ensure Uvicorn is running (e.g. uvicorn app.main:app --reload).",
            file=sys.stderr,
        )
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed repeatable FraudTrace AI demo transactions via the API."
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("FRAUDTRACE_API_URL", "http://127.0.0.1:8000"),
        help="Backend base URL (default: http://127.0.0.1:8000)",
    )
    args = parser.parse_args()
    raise SystemExit(seed_demo_data(args.api_url))


if __name__ == "__main__":
    main()
