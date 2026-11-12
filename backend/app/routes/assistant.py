"""
FraudTrace AI — Investigation Assistant API Routes
===================================================
Endpoints:
- GET  /api/v1/assistant/status — Non-sensitive AI provider readiness & privacy policy status.
- POST /api/v1/assistant/chat   — Stateless, evidence-grounded investigation explanation endpoint.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import (
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantStatusResponse,
)
from app.services.ai_provider import AIProviderError
from app.services.assistant_context import ContextNotFoundError
from app.services.assistant_service import (
    ask_investigation_assistant,
    get_assistant_status,
)

logger = logging.getLogger("fraudtrace.assistant.routes")

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])


@router.get(
    "/status",
    response_model=AssistantStatusResponse,
    summary="Get non-sensitive AI Investigation Assistant readiness status",
)
def read_assistant_status() -> AssistantStatusResponse:
    """
    Reports whether the AI Investigation Assistant is enabled, configured, and
    compliant with external data-classification rules without exposing secrets.
    """
    return get_assistant_status()


@router.post(
    "/chat",
    response_model=AssistantChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Ask an evidence-grounded question about FraudTrace AI records",
)
def chat_with_assistant(
    payload: AssistantChatRequest,
    db: Session = Depends(get_db),
) -> AssistantChatResponse:
    """
    Retrieves scoped, privacy-sanitized context from FraudTrace AI records,
    invokes the configured external AI provider (if enabled and permitted),
    validates all returned citations against retrieved records, and returns
    a structured, grounded explanation.
    """
    try:
        return ask_investigation_assistant(db=db, request=payload)
    except ContextNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc
    except AIProviderError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Unexpected assistant route error: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while generating the investigation explanation.",
        ) from exc
