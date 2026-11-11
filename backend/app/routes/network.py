"""
FraudTrace AI — Fraud Network Intelligence API Routes
=====================================================
Endpoints:
- GET /api/v1/network/overview                — High-level graph statistics & detected lead summary.
- GET /api/v1/network/accounts/{account_id}   — 1–2 hop graph connections and leads for an account.
- GET /api/v1/network/patterns                — Paginated list of suspicious structural patterns.
"""

from collections import Counter
from typing import Optional

import networkx as nx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import (
    AccountNetworkResponse,
    ConnectedAccountResponse,
    NetworkOverviewResponse,
    NetworkPatternListResponse,
    NetworkPatternResponse,
)
from app.services.fraud_graph import (
    NetworkPattern,
    build_transaction_graph,
    detect_all_patterns,
    get_account_connections,
)

router = APIRouter(prefix="/api/v1/network", tags=["network"])


def _to_pattern_response(p: NetworkPattern) -> NetworkPatternResponse:
    """Helper to convert internal NetworkPattern dataclass into Pydantic schema."""
    return NetworkPatternResponse(
        pattern_type=p.pattern_type,
        involved_accounts=p.involved_accounts,
        transaction_references=p.transaction_references,
        explanation=p.explanation,
        severity=p.severity,
        supporting_counts=p.supporting_counts,
        timestamps=p.timestamps,
    )


@router.get(
    "/overview",
    response_model=NetworkOverviewResponse,
    summary="Get transaction network overview and detected investigation leads",
)
def get_network_overview(db: Session = Depends(get_db)) -> NetworkOverviewResponse:
    """
    Constructs the transaction network graph and summarizes accounts, transactions,
    weakly connected components, and detected structural patterns.
    """
    graph = build_transaction_graph(db)
    total_accounts = graph.number_of_nodes()
    total_transactions = graph.number_of_edges()

    if total_accounts == 0:
        return NetworkOverviewResponse(
            total_accounts=0,
            total_transactions=0,
            connected_components=0,
            suspicious_patterns_detected=0,
            suspicious_account_identifiers=[],
            patterns_summary={},
        )

    components = nx.number_weakly_connected_components(graph)
    patterns = detect_all_patterns(graph)

    suspicious_accounts = sorted(
        {acct for p in patterns for acct in p.involved_accounts}
    )
    summary_counts = dict(Counter(p.pattern_type for p in patterns))

    return NetworkOverviewResponse(
        total_accounts=total_accounts,
        total_transactions=total_transactions,
        connected_components=components,
        suspicious_patterns_detected=len(patterns),
        suspicious_account_identifiers=suspicious_accounts,
        patterns_summary=summary_counts,
    )


@router.get(
    "/accounts/{account_id}",
    response_model=AccountNetworkResponse,
    summary="Get network intelligence and 1–2 hop connections for a specific account",
)
def get_account_network(
    account_id: str,
    db: Session = Depends(get_db),
) -> AccountNetworkResponse:
    """
    Inspects the transaction network around `account_id`:
    - Incoming & outgoing transaction counts
    - Connected accounts within 1 or 2 graph hops
    - Relevant suspicious patterns involving this account
    - Related transaction references
    """
    graph = build_transaction_graph(db)

    if account_id not in graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Account '{account_id}' not found in transaction network.",
        )

    in_edges = list(graph.in_edges(account_id, data=True))
    out_edges = list(graph.out_edges(account_id, data=True))

    connections = get_account_connections(graph, account_id, max_hops=2)
    all_patterns = detect_all_patterns(graph)
    relevant = [_to_pattern_response(p) for p in all_patterns if account_id in p.involved_accounts]

    related_refs = sorted(
        {data["reference"] for _, _, data in (in_edges + out_edges)}
    )

    return AccountNetworkResponse(
        account_id=account_id,
        incoming_transaction_count=len(in_edges),
        outgoing_transaction_count=len(out_edges),
        connected_accounts=[
            ConnectedAccountResponse(
                account_id=c.account_id,
                hop_distance=c.hop_distance,
                relationship=c.relationship,
            )
            for c in connections
        ],
        relevant_patterns=relevant,
        related_transaction_references=related_refs,
    )


@router.get(
    "/patterns",
    response_model=NetworkPatternListResponse,
    summary="List detected suspicious network patterns",
)
def list_network_patterns(
    limit: int = Query(default=50, ge=1, le=200, description="Max patterns to return"),
    offset: int = Query(default=0, ge=0, description="Number of patterns to skip"),
    pattern_type: Optional[str] = Query(default=None, description="Filter by pattern type"),
    db: Session = Depends(get_db),
) -> NetworkPatternListResponse:
    """
    Returns detected graph patterns across the transaction network with pagination.
    """
    graph = build_transaction_graph(db)
    patterns = detect_all_patterns(graph)

    if pattern_type:
        filter_upper = pattern_type.strip().upper()
        patterns = [p for p in patterns if p.pattern_type == filter_upper]

    total = len(patterns)
    sliced = patterns[offset : offset + limit]

    return NetworkPatternListResponse(
        items=[_to_pattern_response(p) for p in sliced],
        total=total,
        limit=limit,
        offset=offset,
    )
