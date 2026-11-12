"""
FraudTrace AI — Provider-Independent AI Assistant Abstraction
=============================================================
Defines the provider protocol, environment-driven configuration, privacy
classification gate, sanitized error hierarchy, and the official Google Gemini
Developer API (v1beta REST) implementation.

Security & Privacy Design:
- External AI processing is disabled by default (`AI_ENABLED=false`).
- Credentials (`GEMINI_API_KEY`) are loaded solely from environment variables
  or `backend/.env` and are NEVER logged, returned, or included in exceptions.
- Only `synthetic_demo` investigation context may be sent to external LLM
  providers by default. Non-demo or unclassified classifications are blocked
  unless `AI_ALLOW_EXTERNAL_NON_DEMO=true` is explicitly configured.
- All HTTP requests enforce strict timeouts, bounded output token limits,
  validated HTTPS endpoints, and sanitized error messages.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from dotenv import dotenv_values
import httpx

logger = logging.getLogger("fraudtrace.assistant.provider")

DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"

DEFAULT_AI_PROVIDER = "gemini"
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_THINKING_LEVEL = "low"
DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
DEFAULT_TIMEOUT_SECONDS = 30.0
MIN_TIMEOUT_SECONDS = 2.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_OUTPUT_TOKENS = 1500
MIN_MAX_OUTPUT_TOKENS = 128
MAX_MAX_OUTPUT_TOKENS = 4096
DEFAULT_DATA_CLASSIFICATION = "synthetic_demo"

ALLOWED_DEMO_CLASSIFICATIONS = frozenset({"synthetic_demo", "demo", "synthetic"})
SAFE_MODEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{2,80}$")
SAFE_GROQ_MODEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{2,100}$")

# Structured JSON schema enforced via Gemini `generationConfig.responseJsonSchema`
ASSISTANT_STRUCTURED_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer": {
            "type": "string",
            "description": (
                "Clear, evidence-grounded explanation separating observed facts, "
                "interpretations, and recommended next verification steps."
            ),
        },
        "citations": {
            "type": "array",
            "description": "Citations referencing ONLY exact citation_id values present in supplied context.",
            "items": {
                "type": "object",
                "properties": {
                    "citation_id": {"type": "string"},
                    "claim": {"type": "string"},
                },
                "required": ["citation_id", "claim"],
            },
        },
        "suggested_questions": {
            "type": "array",
            "items": {"type": "string"},
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string"},
        },
        "insufficient_evidence": {
            "type": "boolean",
        },
    },
    "required": ["answer", "citations", "suggested_questions", "limitations"],
}


class AIProviderError(Exception):
    """Base sanitized error for AI assistant configuration and provider calls."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "AI_PROVIDER_ERROR",
        status_code: int = 502,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code
        self.message = message


class AIConfigurationError(AIProviderError):
    """Raised when AI is disabled, misconfigured, or blocked by data-classification rules."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "AI_NOT_CONFIGURED",
        status_code: int = 503,
    ) -> None:
        super().__init__(message, error_code=error_code, status_code=status_code)


class AITimeoutError(AIProviderError):
    """Raised when an upstream LLM provider call exceeds the configured timeout."""

    def __init__(
        self,
        message: str = "AI provider request timed out.",
        *,
        timeout_category: Optional[str] = None,
    ) -> None:
        super().__init__(message, error_code="AI_TIMEOUT", status_code=504)
        self.timeout_category = timeout_category


class AIRateLimitError(AIProviderError):
    """Raised when the upstream LLM provider rejects a call due to quota/rate limits."""

    def __init__(
        self,
        message: str = "AI provider rate limit or quota reached. Please wait and retry.",
    ) -> None:
        super().__init__(message, error_code="AI_RATE_LIMITED", status_code=429)


class AIUpstreamError(AIProviderError):
    """Raised on upstream HTTP, network, or authentication failures (never leaking keys)."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "AI_UPSTREAM_ERROR",
        status_code: int = 502,
        upstream_status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message, error_code=error_code, status_code=status_code)
        self.upstream_status_code = upstream_status_code


class AIInvalidResponseError(AIProviderError):
    """Raised when the provider returns empty, blocked, or invalid structured output."""

    def __init__(
        self,
        message: str = "AI provider returned an unreadable or invalid response format.",
    ) -> None:
        super().__init__(message, error_code="AI_INVALID_RESPONSE", status_code=502)


@dataclass(frozen=True)
class AIAssistantConfig:
    """Validated, environment-driven AI assistant configuration (never leaks secrets)."""

    ai_enabled: bool
    provider: str
    gemini_api_key: Optional[str]
    gemini_model: str
    timeout_seconds: float
    max_output_tokens: int
    data_classification: str
    allow_external_non_demo: bool
    groq_api_key: Optional[str] = None
    groq_model: str = DEFAULT_GROQ_MODEL

    def __repr__(self) -> str:
        return (
            "AIAssistantConfig("
            f"ai_enabled={self.ai_enabled!r}, "
            f"provider={self.provider!r}, "
            f"gemini_model={self.gemini_model!r}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"max_output_tokens={self.max_output_tokens!r}, "
            f"data_classification={self.data_classification!r}, "
            f"allow_external_non_demo={self.allow_external_non_demo!r}, "
            f"api_key_configured={bool(self.gemini_api_key)!r}, "
            "gemini_api_key='***', "
            f"groq_configured={bool(self.groq_api_key)!r}, "
            f"groq_model={self.groq_model!r}, "
            "groq_api_key='***')"
        )


@dataclass(frozen=True)
class ProviderCitationOutput:
    """Raw citation pair returned by an AI provider before server-side verification."""

    citation_id: str
    claim: str


@dataclass(frozen=True)
class ProviderGenerationResult:
    """Validated structured payload returned by an AIProvider implementation."""

    answer: str
    citations: list[ProviderCitationOutput]
    suggested_questions: list[str]
    limitations: list[str]
    insufficient_evidence: bool
    provider: str
    model: str
    raw_finish_reason: Optional[str] = None


@runtime_checkable
class AIProvider(Protocol):
    """Provider-independent interface for grounded FraudTrace AI explanations."""

    provider_name: str
    model_name: str

    def generate_grounded_response(
        self,
        *,
        system_prompt: str,
        user_payload_json: str,
    ) -> ProviderGenerationResult:
        """Generates a structured JSON investigation response from sanitized context."""
        ...


def _parse_bool(raw: Optional[str], *, default: bool = False) -> bool:
    if raw is None:
        return default
    clean = raw.strip().lower()
    if clean in {"1", "true", "yes", "on"}:
        return True
    if clean in {"0", "false", "no", "off", ""}:
        return default if clean == "" else False
    return default


def _parse_bounded_float(
    raw: Optional[str],
    *,
    default: float,
    minimum: float,
    maximum: float,
    env_name: str,
) -> float:
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise AIConfigurationError(
            f"Configuration '{env_name}' must be a valid number.",
            error_code="AI_INVALID_CONFIG",
        ) from exc
    if value < minimum or value > maximum:
        raise AIConfigurationError(
            f"Configuration '{env_name}' must be between {minimum} and {maximum}.",
            error_code="AI_INVALID_CONFIG",
        )
    return value


def _parse_bounded_int(
    raw: Optional[str],
    *,
    default: int,
    minimum: int,
    maximum: int,
    env_name: str,
) -> int:
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise AIConfigurationError(
            f"Configuration '{env_name}' must be a valid integer.",
            error_code="AI_INVALID_CONFIG",
        ) from exc
    if value < minimum or value > maximum:
        raise AIConfigurationError(
            f"Configuration '{env_name}' must be between {minimum} and {maximum}.",
            error_code="AI_INVALID_CONFIG",
        )
    return value


def _scrub_secret(text: str, secret: Optional[str]) -> str:
    """Removes secret values from any diagnostic text before raising/logging."""
    sanitized = text or ""
    if secret:
        sanitized = sanitized.replace(secret, "[REDACTED_KEY]")
    sanitized = re.sub(r"AIza[0-9A-Za-z_-]{16,}", "[REDACTED_KEY]", sanitized)
    sanitized = re.sub(r"gsk_[0-9A-Za-z_-]{16,}", "[REDACTED_KEY]", sanitized)
    return sanitized


def _classify_timeout_exception(exc: httpx.TimeoutException) -> tuple[str, str, str]:
    """Maps an HTTPX timeout subtype to (exception_class, error_category, phase_label)."""
    if isinstance(exc, httpx.ConnectTimeout):
        return ("ConnectTimeout", "connect_timeout", "connection")
    if isinstance(exc, httpx.ReadTimeout):
        return ("ReadTimeout", "read_timeout", "response read")
    if isinstance(exc, httpx.WriteTimeout):
        return ("WriteTimeout", "write_timeout", "request write")
    if isinstance(exc, httpx.PoolTimeout):
        return ("PoolTimeout", "pool_timeout", "connection pool")
    return (type(exc).__name__, "timeout", "request")


def _classify_http_transport_error(exc: httpx.HTTPError) -> str:
    """Maps a non-timeout HTTPX transport error to a sanitized error category."""
    if isinstance(exc, httpx.ConnectError):
        return "connect_error"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "protocol_error"
    return "transport_error"


def _log_provider_diagnostic(
    *,
    level: int,
    event: str,
    provider: str,
    model: str,
    exception_class: str,
    elapsed_ms: int,
    error_category: str,
    http_status: Optional[int],
) -> None:
    """Logs sanitized provider timing/failure metadata without keys, headers, or bodies."""
    logger.log(
        level,
        "%s provider=%s model=%s exception_class=%s elapsed_ms=%d error_category=%s http_status=%s",
        event,
        provider,
        model,
        exception_class,
        elapsed_ms,
        error_category,
        str(http_status) if http_status is not None else "none",
    )


def load_ai_config(
    *,
    env_path: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> AIAssistantConfig:
    """
    Loads AI assistant configuration from environment variables with fallback to
    `backend/.env`. Explicit process environment variables always take precedence.
    """
    target_env = env_path or DEFAULT_ENV_PATH
    file_values: dict[str, str] = {}
    if target_env.exists():
        loaded = dotenv_values(target_env)
        file_values = {k: v for k, v in loaded.items() if k and v is not None}

    active_env = environ if environ is not None else os.environ

    def _get(name: str) -> Optional[str]:
        if name in active_env:
            return active_env.get(name)
        return file_values.get(name)

    ai_enabled = _parse_bool(_get("AI_ENABLED"), default=False)
    provider = (_get("AI_PROVIDER") or DEFAULT_AI_PROVIDER).strip().lower() or DEFAULT_AI_PROVIDER
    raw_api_key = _get("GEMINI_API_KEY")
    gemini_api_key = raw_api_key.strip() if raw_api_key and raw_api_key.strip() else None

    raw_model = (_get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL).strip()
    gemini_model = raw_model or DEFAULT_GEMINI_MODEL
    if not SAFE_MODEL_NAME_PATTERN.match(gemini_model):
        raise AIConfigurationError(
            "Configured GEMINI_MODEL identifier contains invalid characters.",
            error_code="AI_INVALID_CONFIG",
        )

    timeout_seconds = _parse_bounded_float(
        _get("AI_REQUEST_TIMEOUT_SECONDS"),
        default=DEFAULT_TIMEOUT_SECONDS,
        minimum=MIN_TIMEOUT_SECONDS,
        maximum=MAX_TIMEOUT_SECONDS,
        env_name="AI_REQUEST_TIMEOUT_SECONDS",
    )
    max_output_tokens = _parse_bounded_int(
        _get("AI_MAX_OUTPUT_TOKENS"),
        default=DEFAULT_MAX_OUTPUT_TOKENS,
        minimum=MIN_MAX_OUTPUT_TOKENS,
        maximum=MAX_MAX_OUTPUT_TOKENS,
        env_name="AI_MAX_OUTPUT_TOKENS",
    )

    raw_classification = _get("AI_DATA_CLASSIFICATION")
    if raw_classification is None:
        data_classification = DEFAULT_DATA_CLASSIFICATION
    else:
        data_classification = raw_classification.strip().lower() or "unclassified"

    raw_groq_key = _get("GROQ_API_KEY")
    groq_api_key = raw_groq_key.strip() if raw_groq_key and raw_groq_key.strip() else None

    raw_groq_model = (_get("GROQ_MODEL") or DEFAULT_GROQ_MODEL).strip()
    groq_model = raw_groq_model or DEFAULT_GROQ_MODEL
    if not SAFE_GROQ_MODEL_NAME_PATTERN.match(groq_model):
        raise AIConfigurationError(
            "Configured GROQ_MODEL identifier contains invalid characters.",
            error_code="AI_INVALID_CONFIG",
        )

    allow_external_non_demo = _parse_bool(_get("AI_ALLOW_EXTERNAL_NON_DEMO"), default=False)

    return AIAssistantConfig(
        ai_enabled=ai_enabled,
        provider=provider,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        timeout_seconds=timeout_seconds,
        max_output_tokens=max_output_tokens,
        data_classification=data_classification,
        allow_external_non_demo=allow_external_non_demo,
        groq_api_key=groq_api_key,
        groq_model=groq_model,
    )


def validate_external_ai_policy(config: AIAssistantConfig) -> None:
    """
    Enforces enablement, privacy classification policy, and credential presence
    before any context leaves the local server.
    """
    if not config.ai_enabled:
        raise AIConfigurationError(
            "AI Investigation Assistant is disabled (AI_ENABLED=false). "
            "Set AI_ENABLED=true and provide GEMINI_API_KEY in backend/.env to enable external explanations.",
            error_code="AI_DISABLED",
            status_code=503,
        )

    is_demo_data = config.data_classification in ALLOWED_DEMO_CLASSIFICATIONS
    if not is_demo_data and not config.allow_external_non_demo:
        raise AIConfigurationError(
            f"External AI processing is blocked for AI_DATA_CLASSIFICATION='{config.data_classification}'. "
            "Only synthetic/demo data may be sent to external LLM endpoints by default. "
            "Set AI_ALLOW_EXTERNAL_NON_DEMO=true only after reviewing your provider's privacy terms.",
            error_code="AI_PRIVACY_POLICY_BLOCKED",
            status_code=403,
        )

    if config.provider == "gemini" and not config.gemini_api_key:
        raise AIConfigurationError(
            "GEMINI_API_KEY is not configured. Add a Gemini API key to backend/.env "
            "before enabling AI Investigation Assistant requests.",
            error_code="GEMINI_API_KEY_MISSING",
            status_code=503,
        )

    if config.provider == "groq" and not config.groq_api_key:
        raise AIConfigurationError(
            "GROQ_API_KEY is not configured. Add a Groq API key to backend/.env "
            "before enabling AI Investigation Assistant requests.",
            error_code="GROQ_API_KEY_MISSING",
            status_code=503,
        )


def parse_structured_provider_json(
    raw_text: str,
    *,
    provider_name: str,
    model_name: str,
    finish_reason: Optional[str] = None,
) -> ProviderGenerationResult:
    """Parses and validates JSON text returned by an LLM into ProviderGenerationResult."""
    cleaned = (raw_text or "").strip()
    if not cleaned:
        raise AIInvalidResponseError("AI provider returned an empty response body.")

    # Defensive strip if a model wraps JSON inside markdown fences
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise AIInvalidResponseError(
            "AI provider response was not valid JSON matching the grounded schema."
        ) from exc

    if not isinstance(parsed, dict):
        raise AIInvalidResponseError("AI provider response JSON must be an object.")

    answer = parsed.get("answer")
    if not isinstance(answer, str) or not answer.strip():
        raise AIInvalidResponseError("AI provider response is missing a non-empty 'answer' field.")

    raw_citations = parsed.get("citations", [])
    if not isinstance(raw_citations, list):
        raise AIInvalidResponseError("AI provider response field 'citations' must be a list.")

    citations: list[ProviderCitationOutput] = []
    for item in raw_citations:
        if not isinstance(item, dict):
            continue
        cid = item.get("citation_id")
        claim = item.get("claim")
        if isinstance(cid, str) and cid.strip() and isinstance(claim, str) and claim.strip():
            citations.append(
                ProviderCitationOutput(citation_id=cid.strip(), claim=claim.strip())
            )

    raw_suggested = parsed.get("suggested_questions", [])
    suggested_questions = [
        q.strip()
        for q in (raw_suggested if isinstance(raw_suggested, list) else [])
        if isinstance(q, str) and q.strip()
    ][:5]

    raw_limitations = parsed.get("limitations", [])
    limitations = [
        item.strip()
        for item in (raw_limitations if isinstance(raw_limitations, list) else [])
        if isinstance(item, str) and item.strip()
    ][:8]

    insufficient_evidence = bool(parsed.get("insufficient_evidence", False))

    return ProviderGenerationResult(
        answer=answer.strip(),
        citations=citations,
        suggested_questions=suggested_questions,
        limitations=limitations,
        insufficient_evidence=insufficient_evidence,
        provider=provider_name,
        model=model_name,
        raw_finish_reason=finish_reason,
    )


class GeminiProvider:
    """
    Google Gemini Developer API provider using the official v1beta `generateContent`
    endpoint over HTTPS with `x-goog-api-key` header authentication.
    """

    provider_name = "gemini"

    def __init__(
        self,
        config: AIAssistantConfig,
        *,
        base_url: str = DEFAULT_GEMINI_BASE_URL,
        thinking_level: Optional[str] = DEFAULT_GEMINI_THINKING_LEVEL,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if not config.gemini_api_key:
            raise AIConfigurationError(
                "GEMINI_API_KEY is missing.",
                error_code="GEMINI_API_KEY_MISSING",
                status_code=503,
            )
        self._api_key = config.gemini_api_key
        self.model_name = config.gemini_model
        self._timeout_seconds = config.timeout_seconds
        self._max_output_tokens = config.max_output_tokens
        self._base_url = base_url.rstrip("/")
        self._thinking_level = thinking_level
        self._transport = transport

    def generate_grounded_response(
        self,
        *,
        system_prompt: str,
        user_payload_json: str,
    ) -> ProviderGenerationResult:
        url = f"{self._base_url}/models/{self.model_name}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self._api_key,
        }
        generation_config: dict[str, Any] = {
            "temperature": 0.2,
            "maxOutputTokens": self._max_output_tokens,
            "responseMimeType": "application/json",
            "responseJsonSchema": ASSISTANT_STRUCTURED_OUTPUT_SCHEMA,
        }
        if self._thinking_level:
            generation_config["thinkingConfig"] = {
                "thinkingLevel": self._thinking_level,
            }
        body: dict[str, Any] = {
            "system_instruction": {
                "parts": [{"text": system_prompt}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_payload_json}],
                }
            ],
            "generationConfig": generation_config,
        }

        payload = _execute_provider_post(
            provider_name=self.provider_name,
            model_name=self.model_name,
            provider_label="Gemini",
            url=url,
            headers=headers,
            body=body,
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            api_key=self._api_key,
            key_env_name="GEMINI_API_KEY",
        )
        return self._extract_candidate_result(payload)

    def _extract_candidate_result(self, payload: Any) -> ProviderGenerationResult:
        if not isinstance(payload, dict):
            raise AIInvalidResponseError("Unexpected Gemini response root structure.")

        prompt_feedback = payload.get("promptFeedback")
        if isinstance(prompt_feedback, dict) and prompt_feedback.get("blockReason"):
            raise AIInvalidResponseError(
                "Gemini declined to generate output due to safety/policy blocking."
            )

        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise AIInvalidResponseError("Gemini API response contained no candidate output.")

        first = candidates[0]
        if not isinstance(first, dict):
            raise AIInvalidResponseError("Gemini candidate payload had an unexpected format.")

        finish_reason = first.get("finishReason")
        if finish_reason in {"SAFETY", "RECITATION", "PROHIBITED_CONTENT", "SPII"}:
            raise AIInvalidResponseError(
                f"Gemini output halted with finishReason={finish_reason}."
            )

        content = first.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            raise AIInvalidResponseError("Gemini candidate content contained no text parts.")

        text_chunks = [
            part.get("text", "")
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        combined_text = "".join(text_chunks).strip()
        return parse_structured_provider_json(
            combined_text,
            provider_name=self.provider_name,
            model_name=self.model_name,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
        )


def _is_strict_json_schema_compatible(schema: Any) -> bool:
    """
    Checks whether a JSON Schema satisfies OpenAI/Groq strict mode requirements:
    every object node requires `additionalProperties: false` and every property listed
    in `required`.
    """
    if not isinstance(schema, dict):
        return False
    node_type = schema.get("type")
    if node_type == "object":
        if schema.get("additionalProperties") is not False:
            return False
        props = schema.get("properties")
        required = schema.get("required")
        if isinstance(props, dict):
            if not isinstance(required, list) or not set(props.keys()).issubset(set(required)):
                return False
            return all(_is_strict_json_schema_compatible(sub) for sub in props.values())
    elif node_type == "array" and "items" in schema:
        return _is_strict_json_schema_compatible(schema["items"])
    return True


def build_groq_response_format(schema: dict[str, Any]) -> dict[str, Any]:
    """
    Translates ASSISTANT_STRUCTURED_OUTPUT_SCHEMA into Groq's OpenAI-compatible
    `response_format`. Because ASSISTANT_STRUCTURED_OUTPUT_SCHEMA omits
    `additionalProperties: false` and leaves `insufficient_evidence` optional,
    this selects Groq's supported best-effort `json_schema` mode (`strict=False`)
    when strict constraints are not met.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "fraudtrace_assistant_response",
            "strict": _is_strict_json_schema_compatible(schema),
            "schema": schema,
        },
    }


def _raise_for_http_error(
    *,
    response: httpx.Response,
    elapsed_ms: int,
    provider_name: str,
    model_name: str,
    provider_label: str,
    api_key: str,
    key_env_name: str,
) -> None:
    status_code = response.status_code
    category_by_status = {
        429: "rate_limit",
        401: "auth_error",
        403: "auth_error",
        404: "model_unavailable",
    }
    _log_provider_diagnostic(
        level=logging.WARNING,
        event="AI provider HTTP error",
        provider=provider_name,
        model=model_name,
        exception_class="HTTPStatusError",
        elapsed_ms=elapsed_ms,
        error_category=category_by_status.get(status_code, "upstream_http_error"),
        http_status=status_code,
    )

    if status_code == 429:
        raise AIRateLimitError()
    if status_code in (401, 403):
        raise AIUpstreamError(
            f"{provider_label} API authentication or permission check failed. Verify {key_env_name} and model access.",
            error_code="AI_AUTH_ERROR",
            status_code=502,
            upstream_status_code=status_code,
        )
    if status_code == 404:
        raise AIUpstreamError(
            f"Configured {provider_label} model '{model_name}' was not found or is unavailable.",
            error_code="AI_MODEL_UNAVAILABLE",
            status_code=502,
            upstream_status_code=status_code,
        )

    detail_hint = ""
    try:
        err_json = response.json()
        raw_msg = (err_json.get("error") or {}).get("message")
        if isinstance(raw_msg, str) and raw_msg.strip():
            detail_hint = f" ({_scrub_secret(raw_msg.strip()[:160], api_key)})"
    except Exception:
        pass
    raise AIUpstreamError(
        f"{provider_label} API returned HTTP {status_code}{detail_hint}.",
        error_code="AI_UPSTREAM_ERROR",
        status_code=502,
        upstream_status_code=status_code,
    )


def _execute_provider_post(
    *,
    provider_name: str,
    model_name: str,
    provider_label: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    timeout_seconds: float,
    transport: Optional[httpx.BaseTransport],
    api_key: str,
    key_env_name: str,
) -> Any:
    started = time.monotonic()
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            transport=transport,
        ) as client:
            response = client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        exc_class, error_category, phase_label = _classify_timeout_exception(exc)
        _log_provider_diagnostic(
            level=logging.WARNING,
            event="AI provider call timed out",
            provider=provider_name,
            model=model_name,
            exception_class=exc_class,
            elapsed_ms=elapsed_ms,
            error_category=error_category,
            http_status=None,
        )
        raise AITimeoutError(
            f"{provider_label} {phase_label} timed out after {timeout_seconds:.0f}s ({exc_class}).",
            timeout_category=error_category,
        ) from exc
    except httpx.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        _log_provider_diagnostic(
            level=logging.WARNING,
            event="AI provider transport error",
            provider=provider_name,
            model=model_name,
            exception_class=type(exc).__name__,
            elapsed_ms=elapsed_ms,
            error_category=_classify_http_transport_error(exc),
            http_status=None,
        )
        raise AIUpstreamError(
            f"Unable to reach {provider_label} API due to a network or TLS transport error."
        ) from exc

    elapsed_ms = int((time.monotonic() - started) * 1000)

    if response.status_code >= 400:
        _raise_for_http_error(
            response=response,
            elapsed_ms=elapsed_ms,
            provider_name=provider_name,
            model_name=model_name,
            provider_label=provider_label,
            api_key=api_key,
            key_env_name=key_env_name,
        )

    _log_provider_diagnostic(
        level=logging.INFO,
        event="AI provider call completed",
        provider=provider_name,
        model=model_name,
        exception_class="none",
        elapsed_ms=elapsed_ms,
        error_category="none",
        http_status=response.status_code,
    )

    try:
        return response.json()
    except ValueError as exc:
        raise AIInvalidResponseError(f"{provider_label} API did not return valid JSON.") from exc


class GroqProvider:
    """
    Groq OpenAI-compatible Chat Completions provider using `Authorization: Bearer`
    header authentication and structured JSON Schema output (`openai/gpt-oss-20b`).
    """

    provider_name = "groq"

    def __init__(
        self,
        config: AIAssistantConfig,
        *,
        base_url: str = DEFAULT_GROQ_BASE_URL,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if not config.groq_api_key:
            raise AIConfigurationError(
                "GROQ_API_KEY is missing.",
                error_code="GROQ_API_KEY_MISSING",
                status_code=503,
            )
        self._api_key = config.groq_api_key
        self.model_name = config.groq_model
        self._timeout_seconds = config.timeout_seconds
        self._max_output_tokens = config.max_output_tokens
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    def generate_grounded_response(
        self,
        *,
        system_prompt: str,
        user_payload_json: str,
    ) -> ProviderGenerationResult:
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }
        body: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload_json},
            ],
            "temperature": 0.2,
            "max_completion_tokens": self._max_output_tokens,
            "response_format": build_groq_response_format(ASSISTANT_STRUCTURED_OUTPUT_SCHEMA),
        }
        if self.model_name.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"

        payload = _execute_provider_post(
            provider_name=self.provider_name,
            model_name=self.model_name,
            provider_label="Groq",
            url=url,
            headers=headers,
            body=body,
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            api_key=self._api_key,
            key_env_name="GROQ_API_KEY",
        )
        return self._extract_choice_result(payload)

    def _extract_choice_result(self, payload: Any) -> ProviderGenerationResult:
        if not isinstance(payload, dict):
            raise AIInvalidResponseError("Unexpected Groq response root structure.")

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AIInvalidResponseError("Groq API response contained no completion choices.")

        first = choices[0]
        if not isinstance(first, dict):
            raise AIInvalidResponseError("Groq completion choice had an unexpected format.")

        finish_reason = first.get("finish_reason")
        if finish_reason == "content_filter":
            raise AIInvalidResponseError("Groq declined to generate output due to safety/policy blocking.")

        message = first.get("message")
        if not isinstance(message, dict):
            raise AIInvalidResponseError("Groq completion choice contained no message object.")

        if isinstance(message.get("refusal"), str) and message.get("refusal", "").strip():
            raise AIInvalidResponseError("Groq declined to generate output due to safety/policy blocking.")

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise AIInvalidResponseError("Groq completion message contained no text content.")

        return parse_structured_provider_json(
            content,
            provider_name=self.provider_name,
            model_name=self.model_name,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
        )


def get_ai_provider(
    config: AIAssistantConfig,
    *,
    transport: Optional[httpx.BaseTransport] = None,
) -> AIProvider:
    """Factory validating policy and instantiating the configured primary AIProvider."""
    validate_external_ai_policy(config)

    if config.provider == "gemini":
        return GeminiProvider(config, transport=transport)
    if config.provider == "groq":
        return GroqProvider(config, transport=transport)

    raise AIConfigurationError(
        f"Unsupported AI_PROVIDER='{config.provider}'. Supported providers: gemini, groq.",
        error_code="AI_UNSUPPORTED_PROVIDER",
        status_code=503,
    )


def get_fallback_ai_provider(
    config: AIAssistantConfig,
    *,
    transport: Optional[httpx.BaseTransport] = None,
) -> Optional[AIProvider]:
    """
    Instantiates the optional Groq fallback provider only when Gemini is primary
    and `GROQ_API_KEY` is configured. Returns None when fallback is not configured.
    """
    validate_external_ai_policy(config)

    if config.provider == "gemini" and config.groq_api_key:
        return GroqProvider(config, transport=transport)
    return None
