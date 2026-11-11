"""
FraudTrace AI — Fraud Network Intelligence Service
====================================================
Constructs a directed multi-graph of financial transactions using NetworkX
to uncover structural patterns and investigative leads across accounts.

Graph representation:
- Nodes: Account identifiers (sender_id / receiver_id).
- Directed Edges: Transactions from sender -> receiver with preserved attributes
  (transaction_id, reference, amount, currency, timestamp).

Note: Graph patterns highlight structural anomalies as investigation leads;
they are NOT proof of fraud, money laundering, or criminal guilt.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Optional

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Transaction
from app.services.risk_engine import ensure_utc


@dataclass
class NetworkPattern:
    """Represents an explainable graph pattern finding."""
    pattern_type: str
    involved_accounts: list[str]
    transaction_references: list[str]
    explanation: str
    severity: str
    supporting_counts: dict[str, int] = field(default_factory=dict)
    timestamps: list[datetime] = field(default_factory=list)


@dataclass
class ConnectedAccountInfo:
    """Represents a neighbor connected to a target account within 1–2 hops."""
    account_id: str
    hop_distance: int
    relationship: str  # "incoming", "outgoing", "bidirectional", or "indirect_2_hop"


def build_transaction_graph(db: Session) -> nx.MultiDiGraph:
    """
    Loads persisted transactions from SQLAlchemy and builds a NetworkX MultiDiGraph.
    Multiple transactions between the same accounts are preserved as separate edges.
    """
    graph = nx.MultiDiGraph()

    txns = db.execute(
        select(Transaction).order_by(Transaction.timestamp.asc(), Transaction.id.asc())
    ).scalars().all()

    for txn in txns:
        ts = ensure_utc(txn.timestamp)
        graph.add_node(txn.sender_id)
        graph.add_node(txn.receiver_id)
        graph.add_edge(
            txn.sender_id,
            txn.receiver_id,
            transaction_id=txn.id,
            reference=txn.reference,
            amount=txn.amount,
            currency=txn.currency,
            timestamp=ts,
        )

    return graph


def detect_high_volume_receivers(
    graph: nx.MultiDiGraph,
    min_distinct_senders: int = 3,
    window_minutes: int = 60,
) -> list[NetworkPattern]:
    """
    Pattern 1: HIGH_VOLUME_RECEIVER
    Detects accounts receiving transactions from at least `min_distinct_senders`
    distinct sender accounts within a configurable rolling time window.
    """
    patterns: list[NetworkPattern] = []
    window_delta = timedelta(minutes=window_minutes)

    for receiver in sorted(graph.nodes()):
        in_edges = list(graph.in_edges(receiver, data=True))
        if len(in_edges) < min_distinct_senders:
            continue

        # Sort incoming edges chronologically
        sorted_edges = sorted(in_edges, key=lambda edge: edge[2]["timestamp"])

        # Sliding window to find the window with maximum distinct senders
        best_window_edges: list[tuple[str, str, dict[str, Any]]] = []
        best_senders: set[str] = set()

        for i, (_, _, start_data) in enumerate(sorted_edges):
            t_start = start_data["timestamp"]
            t_end = t_start + window_delta

            current_edges = [
                edge for edge in sorted_edges[i:]
                if t_start <= edge[2]["timestamp"] <= t_end
            ]
            current_senders = {u for u, _, _ in current_edges}

            if len(current_senders) >= min_distinct_senders:
                if len(current_senders) > len(best_senders) or (
                    len(current_senders) == len(best_senders)
                    and len(current_edges) > len(best_window_edges)
                ):
                    best_senders = current_senders
                    best_window_edges = current_edges

        if best_window_edges and len(best_senders) >= min_distinct_senders:
            sorted_senders = sorted(best_senders)
            refs = [data["reference"] for _, _, data in best_window_edges]
            times = sorted([data["timestamp"] for _, _, data in best_window_edges])
            severity = "HIGH" if len(best_senders) >= 5 else "MEDIUM"

            explanation = (
                f"High-volume receiver indicator: Account '{receiver}' received {len(best_window_edges)} "
                f"transactions from {len(best_senders)} distinct senders within a {window_minutes}-minute window "
                f"(threshold: {min_distinct_senders} senders). Recommended for review as an investigation lead."
            )

            patterns.append(
                NetworkPattern(
                    pattern_type="HIGH_VOLUME_RECEIVER",
                    involved_accounts=[receiver] + sorted_senders,
                    transaction_references=refs,
                    explanation=explanation,
                    severity=severity,
                    supporting_counts={
                        "distinct_senders": len(best_senders),
                        "incoming_transactions": len(best_window_edges),
                        "window_minutes": window_minutes,
                    },
                    timestamps=times,
                )
            )

    return patterns


def detect_rapid_fund_movement(
    graph: nx.MultiDiGraph,
    max_delay_minutes: int = 30,
) -> list[NetworkPattern]:
    """
    Pattern 2: RAPID_FUND_MOVEMENT
    Detects an account receiving funds and sending funds onward within a short
    time window (`max_delay_minutes`).
    """
    patterns: list[NetworkPattern] = []
    max_delta = timedelta(minutes=max_delay_minutes)

    for node in sorted(graph.nodes()):
        in_edges = list(graph.in_edges(node, data=True))
        out_edges = list(graph.out_edges(node, data=True))

        if not in_edges or not out_edges:
            continue

        matched_in_refs: set[str] = set()
        matched_out_refs: set[str] = set()
        matched_accounts: set[str] = {node}
        matched_timestamps: list[datetime] = []
        min_delay_seconds: Optional[float] = None
        pair_count = 0

        for u, _, in_data in in_edges:
            in_ts = in_data["timestamp"]
            for _, v, out_data in out_edges:
                out_ts = out_data["timestamp"]
                if in_ts <= out_ts <= in_ts + max_delta:
                    pair_count += 1
                    delay_sec = (out_ts - in_ts).total_seconds()
                    if min_delay_seconds is None or delay_sec < min_delay_seconds:
                        min_delay_seconds = delay_sec

                    matched_in_refs.add(in_data["reference"])
                    matched_out_refs.add(out_data["reference"])
                    matched_accounts.add(u)
                    matched_accounts.add(v)
                    matched_timestamps.extend([in_ts, out_ts])

        if pair_count > 0:
            all_refs = sorted(matched_in_refs | matched_out_refs)
            unique_times = sorted(set(matched_timestamps))
            other_accounts = sorted(matched_accounts - {node})
            delay_display = (
                f"{int(min_delay_seconds)} second(s)"
                if min_delay_seconds is not None and min_delay_seconds < 60
                else f"{(min_delay_seconds or 0) / 60:.1f} minute(s)"
            )
            severity = "HIGH" if (min_delay_seconds is not None and min_delay_seconds <= 300) or pair_count >= 2 else "MEDIUM"

            explanation = (
                f"Rapid fund movement indicator: Account '{node}' received incoming funds and sent outgoing funds "
                f"onward within {delay_display} (threshold: {max_delay_minutes} minutes, {pair_count} rapid sequence(s) observed). "
                f"This timing pattern is an investigation lead and does not independently establish illicit intent."
            )

            patterns.append(
                NetworkPattern(
                    pattern_type="RAPID_FUND_MOVEMENT",
                    involved_accounts=[node] + other_accounts,
                    transaction_references=all_refs,
                    explanation=explanation,
                    severity=severity,
                    supporting_counts={
                        "rapid_transfer_pairs": pair_count,
                        "incoming_transactions": len(matched_in_refs),
                        "outgoing_transactions": len(matched_out_refs),
                        "window_minutes": max_delay_minutes,
                    },
                    timestamps=unique_times,
                )
            )

    return patterns


def detect_shared_receivers(
    graph: nx.MultiDiGraph,
    min_distinct_senders: int = 2,
) -> list[NetworkPattern]:
    """
    Pattern 3: SHARED_RECEIVER
    Detects multiple distinct senders transacting with the same receiver account.
    """
    patterns: list[NetworkPattern] = []

    for receiver in sorted(graph.nodes()):
        in_edges = list(graph.in_edges(receiver, data=True))
        if not in_edges:
            continue

        distinct_senders = sorted({u for u, _, _ in in_edges})
        if len(distinct_senders) >= min_distinct_senders:
            sorted_in_edges = sorted(in_edges, key=lambda edge: edge[2]["timestamp"])
            refs = [data["reference"] for _, _, data in sorted_in_edges]
            times = [data["timestamp"] for _, _, data in sorted_in_edges]
            severity = "MEDIUM" if len(distinct_senders) >= 3 else "LOW"

            explanation = (
                f"Shared receiver indicator: Account '{receiver}' received {len(in_edges)} transaction(s) "
                f"from {len(distinct_senders)} distinct connected sender accounts."
            )

            patterns.append(
                NetworkPattern(
                    pattern_type="SHARED_RECEIVER",
                    involved_accounts=[receiver] + distinct_senders,
                    transaction_references=refs,
                    explanation=explanation,
                    severity=severity,
                    supporting_counts={
                        "distinct_senders": len(distinct_senders),
                        "total_incoming_transactions": len(in_edges),
                    },
                    timestamps=times,
                )
            )

    return patterns


def get_account_connections(
    graph: nx.MultiDiGraph,
    account_id: str,
    max_hops: int = 2,
) -> list[ConnectedAccountInfo]:
    """
    Pattern 4: ACCOUNT_CONNECTIONS
    Finds accounts connected to `account_id` within 1 or 2 graph hops.
    """
    if account_id not in graph:
        return []

    undirected = graph.to_undirected()
    hop_distances = nx.single_source_shortest_path_length(
        undirected, account_id, cutoff=max_hops
    )

    connections: list[ConnectedAccountInfo] = []
    for neighbor, distance in sorted(hop_distances.items(), key=lambda x: (x[1], x[0])):
        if distance == 0:
            continue

        if distance == 1:
            has_in = graph.has_edge(neighbor, account_id)
            has_out = graph.has_edge(account_id, neighbor)
            if has_in and has_out:
                rel = "bidirectional"
            elif has_in:
                rel = "incoming"
            else:
                rel = "outgoing"
        else:
            rel = f"indirect_{distance}_hop"

        connections.append(
            ConnectedAccountInfo(
                account_id=neighbor,
                hop_distance=distance,
                relationship=rel,
            )
        )

    return connections


def detect_all_patterns(graph: nx.MultiDiGraph) -> list[NetworkPattern]:
    """
    Runs all suspicious pattern detectors across the transaction graph
    and aggregates explainable investigation leads.
    """
    if graph.number_of_nodes() == 0:
        return []

    patterns: list[NetworkPattern] = []
    patterns.extend(detect_high_volume_receivers(graph))
    patterns.extend(detect_rapid_fund_movement(graph))
    patterns.extend(detect_shared_receivers(graph))
    return patterns
