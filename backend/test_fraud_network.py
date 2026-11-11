"""
FraudTrace AI — Test Suite: Fraud Network Intelligence
======================================================
Tests:
1. Empty database handling (overview, patterns list, graph creation).
2. Graph creation from persisted transactions (nodes, directed multi-edges, preserved attributes).
3. SHARED_RECEIVER pattern detection & non-triggering single-sender control case.
4. HIGH_VOLUME_RECEIVER pattern detection within rolling window & out-of-window exclusion.
5. RAPID_FUND_MOVEMENT detection (incoming + outgoing references, cautious wording, timing bounds).
6. ACCOUNT_CONNECTIONS traversal (1-hop incoming/outgoing/bidirectional, 2-hop indirect, 3-hop exclusion).
7. Account network API (GET /api/v1/network/accounts/{account_id}) and 404 for missing accounts.
8. Network overview API (connected components, summaries) & pattern pagination/filtering.
9. End-to-end integration from POST /api/v1/transactions/analyze into network intelligence APIs.

ISOLATION:
Uses an isolated temporary SQLite database file (tempfile), leaving `backend/data/fraudtrace.db`
completely untouched.
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

# Ensure `backend` directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import HTTPException
from sqlalchemy import create_engine, delete, event
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app.models import Evidence, Investigation, Transaction
from app.routes.network import (
    get_account_network,
    get_network_overview,
    list_network_patterns,
)
from app.routes.transactions import analyze_transaction
from app.schemas import TransactionAnalyzeRequest
from app.services.fraud_graph import (
    build_transaction_graph,
    detect_all_patterns,
    detect_high_volume_receivers,
    detect_rapid_fund_movement,
    detect_shared_receivers,
    get_account_connections,
)

# ---------------------------------------------------------------------------
# Isolated Test Database Setup (Temporary SQLite file)
# ---------------------------------------------------------------------------
_temp_db_handle = tempfile.NamedTemporaryFile(suffix="_test_network.db", delete=False)
_temp_db_path = Path(_temp_db_handle.name).resolve()
_temp_db_handle.close()

test_engine = create_engine(
    f"sqlite:///{_temp_db_path.as_posix()}",
    connect_args={"check_same_thread": False},
)


@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def setup_test_db() -> None:
    Base.metadata.create_all(bind=test_engine)


def reset_tables(db: Session) -> None:
    """Clear all rows safely between test cases so every test sees a clean state."""
    db.execute(delete(Evidence))
    db.execute(delete(Investigation))
    db.execute(delete(Transaction))
    db.commit()


def cleanup_test_db() -> None:
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    try:
        if _temp_db_path.exists():
            _temp_db_path.unlink()
    except Exception:
        pass


def _add_tx(
    db: Session,
    ref: str,
    sender: str,
    receiver: str,
    amount: str,
    timestamp: datetime,
    currency: str = "USD",
) -> Transaction:
    txn = Transaction(
        reference=ref,
        sender_id=sender,
        receiver_id=receiver,
        amount=Decimal(amount),
        currency=currency,
        timestamp=timestamp,
    )
    db.add(txn)
    return txn


# ---------------------------------------------------------------------------
# Test Functions
# ---------------------------------------------------------------------------

def test_1_empty_database_behavior() -> None:
    """Verify empty DB produces zero stats, empty patterns, and clean graph."""
    print("Test 1: Testing Empty Database Behavior...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)

        graph = build_transaction_graph(db)
        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0
        assert detect_all_patterns(graph) == []

        overview = get_network_overview(db=db)
        assert overview.total_accounts == 0
        assert overview.total_transactions == 0
        assert overview.connected_components == 0
        assert overview.suspicious_patterns_detected == 0
        assert overview.suspicious_account_identifiers == []
        assert overview.patterns_summary == {}

        patterns_page = list_network_patterns(limit=50, offset=0, pattern_type=None, db=db)
        assert patterns_page.total == 0
        assert patterns_page.items == []
        print("✓ Empty database behavior verified.", flush=True)
    finally:
        db.close()


def test_2_graph_creation_and_multi_edge_attributes() -> None:
    """Verify MultiDiGraph builds nodes/edges and preserves transaction attributes."""
    print("Test 2: Testing Graph Creation & Multi-Edge Attributes...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)

        # Two distinct transactions between the exact same sender & receiver
        _add_tx(db, "REF-G1", "ACC_ALICE", "ACC_BOB", "125.50", t0, "USD")
        _add_tx(db, "REF-G2", "ACC_ALICE", "ACC_BOB", "300.00", t0 + timedelta(minutes=5), "EUR")
        db.commit()

        graph = build_transaction_graph(db)
        assert graph.number_of_nodes() == 2
        assert graph.number_of_edges() == 2  # MultiDiGraph must preserve both transactions

        edges_alice_bob = list(graph.get_edge_data("ACC_ALICE", "ACC_BOB").values())
        assert len(edges_alice_bob) == 2
        refs = {edge["reference"] for edge in edges_alice_bob}
        assert refs == {"REF-G1", "REF-G2"}

        by_ref = {edge["reference"]: edge for edge in edges_alice_bob}
        assert by_ref["REF-G1"]["amount"] == Decimal("125.50")
        assert by_ref["REF-G1"]["currency"] == "USD"
        assert by_ref["REF-G1"]["timestamp"] == t0
        assert by_ref["REF-G2"]["amount"] == Decimal("300.00")
        assert by_ref["REF-G2"]["currency"] == "EUR"
        print("✓ Graph creation & edge attributes verified.", flush=True)
    finally:
        db.close()


def test_3_shared_receiver_detection() -> None:
    """Verify SHARED_RECEIVER triggers for >=2 distinct senders and ignores single-sender pairs."""
    print("Test 3: Testing SHARED_RECEIVER Detection...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)

        # Receiver HUB_SHARED receives from 2 distinct senders
        _add_tx(db, "REF-SR-1", "SENDER_1", "HUB_SHARED", "100.00", t0)
        _add_tx(db, "REF-SR-2", "SENDER_2", "HUB_SHARED", "200.00", t0 + timedelta(hours=3))

        # Receiver HUB_SOLO receives 2 transactions from the SAME sender -> must not trigger
        _add_tx(db, "REF-SOLO-1", "SENDER_SOLO", "HUB_SOLO", "50.00", t0)
        _add_tx(db, "REF-SOLO-2", "SENDER_SOLO", "HUB_SOLO", "60.00", t0 + timedelta(minutes=5))
        db.commit()

        graph = build_transaction_graph(db)
        patterns = detect_shared_receivers(graph)
        assert len(patterns) == 1

        p = patterns[0]
        assert p.pattern_type == "SHARED_RECEIVER"
        assert p.severity == "LOW"
        assert set(p.involved_accounts) == {"HUB_SHARED", "SENDER_1", "SENDER_2"}
        assert set(p.transaction_references) == {"REF-SR-1", "REF-SR-2"}
        assert p.supporting_counts["distinct_senders"] == 2
        assert p.supporting_counts["total_incoming_transactions"] == 2
        print("✓ SHARED_RECEIVER detection verified.", flush=True)
    finally:
        db.close()


def test_4_high_volume_receiver_detection() -> None:
    """Verify HIGH_VOLUME_RECEIVER triggers within rolling window and excludes spread-out senders."""
    print("Test 4: Testing HIGH_VOLUME_RECEIVER Detection...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 1, 14, 0, tzinfo=timezone.utc)

        # Case A: 3 distinct senders to HV_TARGET within 20 minutes -> should trigger
        _add_tx(db, "REF-HV-1", "HV_S1", "HV_TARGET", "150.00", t0)
        _add_tx(db, "REF-HV-2", "HV_S2", "HV_TARGET", "175.00", t0 + timedelta(minutes=10))
        _add_tx(db, "REF-HV-3", "HV_S3", "HV_TARGET", "200.00", t0 + timedelta(minutes=20))

        # Case B: 3 distinct senders to SPREAD_TARGET spaced 90 minutes apart -> must NOT trigger (60m window)
        _add_tx(db, "REF-SP-1", "SP_S1", "SPREAD_TARGET", "100.00", t0)
        _add_tx(db, "REF-SP-2", "SP_S2", "SPREAD_TARGET", "100.00", t0 + timedelta(minutes=90))
        _add_tx(db, "REF-SP-3", "SP_S3", "SPREAD_TARGET", "100.00", t0 + timedelta(minutes=180))
        db.commit()

        graph = build_transaction_graph(db)
        hv_patterns = detect_high_volume_receivers(graph, min_distinct_senders=3, window_minutes=60)
        assert len(hv_patterns) == 1

        p = hv_patterns[0]
        assert p.pattern_type == "HIGH_VOLUME_RECEIVER"
        assert p.severity == "MEDIUM"
        assert p.involved_accounts[0] == "HV_TARGET"
        assert set(p.involved_accounts) == {"HV_TARGET", "HV_S1", "HV_S2", "HV_S3"}
        assert p.transaction_references == ["REF-HV-1", "REF-HV-2", "REF-HV-3"]
        assert p.supporting_counts["distinct_senders"] == 3
        assert p.supporting_counts["incoming_transactions"] == 3
        assert "investigation lead" in p.explanation.lower()
        print("✓ HIGH_VOLUME_RECEIVER detection verified.", flush=True)
    finally:
        db.close()


def test_5_rapid_fund_movement_detection() -> None:
    """Verify RAPID_FUND_MOVEMENT identifies incoming+outgoing refs and avoids guilt claims."""
    print("Test 5: Testing RAPID_FUND_MOVEMENT Detection...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 1, 16, 0, tzinfo=timezone.utc)

        # Case A: Rapid relay through RELAY_MULE (in at 16:00, out at 16:04) -> triggers HIGH
        _add_tx(db, "REF-RFM-IN", "ORIGIN_1", "RELAY_MULE", "900.00", t0)
        _add_tx(db, "REF-RFM-OUT", "RELAY_MULE", "DEST_1", "880.00", t0 + timedelta(minutes=4))

        # Case B: Slow relay through SLOW_NODE (in at 16:00, out 2 hours later) -> must NOT trigger in 30m
        _add_tx(db, "REF-SLOW-IN", "ORIGIN_2", "SLOW_NODE", "500.00", t0)
        _add_tx(db, "REF-SLOW-OUT", "SLOW_NODE", "DEST_2", "500.00", t0 + timedelta(hours=2))

        # Case C: Outgoing happens BEFORE incoming on REVERSE_NODE -> must NOT trigger
        _add_tx(db, "REF-REV-OUT", "REVERSE_NODE", "DEST_3", "100.00", t0)
        _add_tx(db, "REF-REV-IN", "ORIGIN_3", "REVERSE_NODE", "100.00", t0 + timedelta(minutes=5))
        db.commit()

        graph = build_transaction_graph(db)
        rfm_patterns = detect_rapid_fund_movement(graph, max_delay_minutes=30)
        assert len(rfm_patterns) == 1

        p = rfm_patterns[0]
        assert p.pattern_type == "RAPID_FUND_MOVEMENT"
        assert p.severity == "HIGH"
        assert p.involved_accounts[0] == "RELAY_MULE"
        assert set(p.involved_accounts) == {"RELAY_MULE", "ORIGIN_1", "DEST_1"}
        assert set(p.transaction_references) == {"REF-RFM-IN", "REF-RFM-OUT"}
        assert p.supporting_counts["incoming_transactions"] == 1
        assert p.supporting_counts["outgoing_transactions"] == 1
        assert "does not independently establish" in p.explanation.lower()
        assert "laundering" not in p.explanation.lower()
        print("✓ RAPID_FUND_MOVEMENT detection verified.", flush=True)
    finally:
        db.close()


def test_6_account_connections_and_hops() -> None:
    """Verify 1-hop relationship labels, 2-hop indirect traversal, and 3-hop exclusion."""
    print("Test 6: Testing ACCOUNT_CONNECTIONS (1-2 Hop Traversal)...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 2, 9, 0, tzinfo=timezone.utc)

        # Build chain: A <-> B -> C -> D and E -> A (E is incoming 1-hop to A)
        _add_tx(db, "REF-C1", "A", "B", "100.00", t0)
        _add_tx(db, "REF-C2", "B", "A", "50.00", t0 + timedelta(minutes=10))
        _add_tx(db, "REF-C3", "B", "C", "40.00", t0 + timedelta(minutes=15))
        _add_tx(db, "REF-C4", "C", "D", "30.00", t0 + timedelta(minutes=20))
        _add_tx(db, "REF-C5", "E", "A", "200.00", t0 - timedelta(minutes=5))
        # Also self-loop on A shouldn't put A in its own connections
        _add_tx(db, "REF-SELF", "A", "A", "10.00", t0 + timedelta(minutes=25))
        db.commit()

        graph = build_transaction_graph(db)
        conns_a = get_account_connections(graph, "A", max_hops=2)
        conn_map = {c.account_id: c for c in conns_a}

        assert "A" not in conn_map
        assert "D" not in conn_map  # 3 hops away from A

        assert conn_map["B"].hop_distance == 1
        assert conn_map["B"].relationship == "bidirectional"

        assert conn_map["E"].hop_distance == 1
        assert conn_map["E"].relationship == "incoming"

        assert conn_map["C"].hop_distance == 2
        assert conn_map["C"].relationship == "indirect_2_hop"

        # Verify 1-hop outgoing from B -> C
        conns_c = get_account_connections(graph, "C", max_hops=1)
        c_map = {c.account_id: c for c in conns_c}
        assert c_map["B"].relationship == "incoming"
        assert c_map["D"].relationship == "outgoing"
        print("✓ ACCOUNT_CONNECTIONS traversal verified.", flush=True)
    finally:
        db.close()


def test_7_account_network_api_and_404() -> None:
    """Verify GET /api/v1/network/accounts/{account_id} data & 404 for unknown account."""
    print("Test 7: Testing Account Network API & Missing Account 404...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 2, 11, 0, tzinfo=timezone.utc)

        _add_tx(db, "REF-API-1", "SRC_1", "TARGET_ACC", "400.00", t0)
        _add_tx(db, "REF-API-2", "SRC_2", "TARGET_ACC", "450.00", t0 + timedelta(minutes=2))
        _add_tx(db, "REF-API-3", "TARGET_ACC", "OUT_ACC", "800.00", t0 + timedelta(minutes=5))
        # Unrelated edge not touching TARGET_ACC
        _add_tx(db, "REF-OTHER", "OUT_ACC", "FAR_ACC", "100.00", t0 + timedelta(minutes=8))
        db.commit()

        profile = get_account_network("TARGET_ACC", db=db)
        assert profile.account_id == "TARGET_ACC"
        assert profile.incoming_transaction_count == 2
        assert profile.outgoing_transaction_count == 1
        assert profile.related_transaction_references == ["REF-API-1", "REF-API-2", "REF-API-3"]

        # FAR_ACC is 2 hops away via TARGET_ACC -> OUT_ACC -> FAR_ACC
        hop_map = {c.account_id: c for c in profile.connected_accounts}
        assert set(hop_map.keys()) == {"SRC_1", "SRC_2", "OUT_ACC", "FAR_ACC"}
        assert hop_map["FAR_ACC"].hop_distance == 2

        pattern_types = {p.pattern_type for p in profile.relevant_patterns}
        assert "SHARED_RECEIVER" in pattern_types
        assert "RAPID_FUND_MOVEMENT" in pattern_types

        # Non-existent account must raise HTTP 404
        caught_404 = False
        try:
            get_account_network("NON_EXISTENT_ACCOUNT", db=db)
        except HTTPException as exc:
            assert exc.status_code == 404
            caught_404 = True
        assert caught_404, "Expected HTTPException 404 for unknown account!"
        print("✓ Account Network API & 404 handling verified.", flush=True)
    finally:
        db.close()


def test_8_network_overview_and_patterns_pagination() -> None:
    """Verify overview component counting and patterns filtering/pagination."""
    print("Test 8: Testing Network Overview & Patterns Pagination/Filtering...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        t0 = datetime(2026, 5, 2, 13, 0, tzinfo=timezone.utc)

        # Component 1: triggers HIGH_VOLUME_RECEIVER & SHARED_RECEIVER on COMP1_HUB
        _add_tx(db, "REF-O1", "C1_S1", "COMP1_HUB", "100.00", t0)
        _add_tx(db, "REF-O2", "C1_S2", "COMP1_HUB", "120.00", t0 + timedelta(minutes=5))
        _add_tx(db, "REF-O3", "C1_S3", "COMP1_HUB", "140.00", t0 + timedelta(minutes=10))
        # Plus rapid fund movement out of COMP1_HUB
        _add_tx(db, "REF-O4", "COMP1_HUB", "C1_OUT", "350.00", t0 + timedelta(minutes=12))

        # Component 2 (disconnected): triggers SHARED_RECEIVER on COMP2_HUB
        _add_tx(db, "REF-O5", "C2_S1", "COMP2_HUB", "200.00", t0)
        _add_tx(db, "REF-O6", "C2_S2", "COMP2_HUB", "210.00", t0 + timedelta(hours=2))
        db.commit()

        overview = get_network_overview(db=db)
        assert overview.total_accounts == 8  # 5 in comp1 + 3 in comp2
        assert overview.total_transactions == 6
        assert overview.connected_components == 2
        assert overview.patterns_summary["HIGH_VOLUME_RECEIVER"] == 1
        assert overview.patterns_summary["RAPID_FUND_MOVEMENT"] == 1
        assert overview.patterns_summary["SHARED_RECEIVER"] == 2
        assert overview.suspicious_patterns_detected == 4

        # Filter by pattern_type (lowercase input should normalize cleanly)
        shared_page = list_network_patterns(
            limit=1,
            offset=1,
            pattern_type="shared_receiver",
            db=db,
        )
        assert shared_page.total == 2
        assert len(shared_page.items) == 1
        assert shared_page.items[0].pattern_type == "SHARED_RECEIVER"
        assert shared_page.limit == 1
        assert shared_page.offset == 1
        print("✓ Network Overview & Patterns pagination verified.", flush=True)
    finally:
        db.close()


def test_9_end_to_end_transaction_analyze_to_network() -> None:
    """Verify transactions submitted via analyze_transaction feed cleanly into network intelligence."""
    print("Test 9: Testing End-to-End Integration (Transaction Analyze -> Network)...", flush=True)
    db = TestingSessionLocal()
    try:
        reset_tables(db)
        base_time = datetime(2026, 5, 3, 15, 0, tzinfo=timezone.utc)

        submissions = [
            ("E2E-NET-1", "E2E_S1", "E2E_COLLECTOR", "150.00", base_time),
            ("E2E-NET-2", "E2E_S2", "E2E_COLLECTOR", "160.00", base_time + timedelta(minutes=3)),
            ("E2E-NET-3", "E2E_S3", "E2E_COLLECTOR", "170.00", base_time + timedelta(minutes=6)),
            ("E2E-NET-4", "E2E_COLLECTOR", "E2E_EXIT", "470.00", base_time + timedelta(minutes=8)),
        ]
        for ref, sender, receiver, amt, ts in submissions:
            req = TransactionAnalyzeRequest(
                reference=ref,
                sender_id=sender,
                receiver_id=receiver,
                amount=Decimal(amt),
                currency="USD",
                timestamp=ts,
            )
            analyze_transaction(payload=req, db=db)

        overview = get_network_overview(db=db)
        assert overview.total_accounts == 5
        assert overview.total_transactions == 4
        assert overview.connected_components == 1
        assert overview.suspicious_patterns_detected == 3

        collector_net = get_account_network("E2E_COLLECTOR", db=db)
        assert collector_net.incoming_transaction_count == 3
        assert collector_net.outgoing_transaction_count == 1
        assert collector_net.related_transaction_references == [
            "E2E-NET-1",
            "E2E-NET-2",
            "E2E-NET-3",
            "E2E-NET-4",
        ]
        assert {p.pattern_type for p in collector_net.relevant_patterns} == {
            "HIGH_VOLUME_RECEIVER",
            "RAPID_FUND_MOVEMENT",
            "SHARED_RECEIVER",
        }
        print("✓ End-to-end transaction analyze -> network integration verified.", flush=True)
    finally:
        db.close()


def run_all_tests() -> None:
    print("==================================================================", flush=True)
    print("FraudTrace AI: Fraud Network Intelligence Test Suite", flush=True)
    print("==================================================================", flush=True)
    setup_test_db()
    try:
        test_1_empty_database_behavior()
        test_2_graph_creation_and_multi_edge_attributes()
        test_3_shared_receiver_detection()
        test_4_high_volume_receiver_detection()
        test_5_rapid_fund_movement_detection()
        test_6_account_connections_and_hops()
        test_7_account_network_api_and_404()
        test_8_network_overview_and_patterns_pagination()
        test_9_end_to_end_transaction_analyze_to_network()

        print("\n==================================================================", flush=True)
        print("ALL 9 NETWORK INTELLIGENCE TEST SUITES PASSED (100% PASS RATE)", flush=True)
        print("==================================================================", flush=True)
    finally:
        cleanup_test_db()


if __name__ == "__main__":
    run_all_tests()
