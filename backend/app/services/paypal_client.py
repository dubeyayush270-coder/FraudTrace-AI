"""
FraudTrace AI — PayPal Sandbox OAuth & Orders v2 Client
========================================================
Provides secure, isolated PayPal Sandbox OAuth 2.0 (`client_credentials`)
in-memory token management and Orders v2 API operations without exposing
credentials, OAuth tokens, or raw API responses in logs, databases, API
payloads, or frontend assets.

Scope:
- Loads `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and `PAYPAL_BASE_URL`
  from `backend/.env`.
- Enforces HTTPS + PayPal Sandbox host constraints (`api-m.sandbox.paypal.com`
  or `*.sandbox.paypal.com`) so live endpoints or HTTP are always rejected.
- Caches OAuth access tokens strictly in memory (`_TokenCacheEntry`) until
  shortly before expiry and refreshes automatically when expired.
- Implements PayPal Orders v2:
  * `create_order` (`POST /v2/checkout/orders`, `intent="CAPTURE"`)
  * `get_order` (`GET /v2/checkout/orders/{order_id}`)
  * `capture_order` (`POST /v2/checkout/orders/{order_id}/capture`)
- Safely maps HTTP, timeout, TLS, and payload errors without disclosing
  Authorization headers, Client Secrets, or Bearer tokens.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import ipaddress
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlparse

from dotenv import dotenv_values
import httpx

DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"
OAUTH_TOKEN_PATH = "/v1/oauth2/token"
ORDERS_V2_PATH = "/v2/checkout/orders"
ALLOWED_SANDBOX_HOST = "api-m.sandbox.paypal.com"
DEFAULT_EXPIRY_SKEW_SECONDS = 60.0
SUPPORTED_PAYPAL_CURRENCIES = frozenset({"USD", "EUR", "GBP", "CAD", "AUD", "CHF", "SGD"})
DEFAULT_PAYPAL_RETURN_URL = "http://localhost:5173/?paypal=return"
DEFAULT_PAYPAL_CANCEL_URL = "http://localhost:5173/?paypal=cancel"
ALLOWED_LOCAL_DEV_HOSTS = frozenset({"localhost", "127.0.0.1"})


class PayPalConfigurationError(ValueError):
    """Raised when required PayPal Sandbox environment configuration is missing or invalid."""


class PayPalAPIError(Exception):
    """Sanitized PayPal API or transport error containing zero secrets or access tokens."""

    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


@dataclass(frozen=True)
class PayPalSandboxConfig:
    """Internal configuration container (must never be logged or serialized)."""

    client_id: str
    client_secret: str
    base_url: str
    return_url: str = DEFAULT_PAYPAL_RETURN_URL
    cancel_url: str = DEFAULT_PAYPAL_CANCEL_URL
    allowed_redirect_hosts: frozenset[str] = ALLOWED_LOCAL_DEV_HOSTS

    def __repr__(self) -> str:
        return (
            f"PayPalSandboxConfig(base_url={self.base_url!r}, "
            f"return_url={self.return_url!r}, cancel_url={self.cancel_url!r}, "
            "client_id='***', client_secret='***')"
        )


@dataclass(frozen=True)
class _TokenCacheEntry:
    """Internal in-memory OAuth token entry (never persisted, serialized, or logged)."""

    access_token: str
    expires_at_monotonic: float
    token_type: Optional[str]
    expires_in: Optional[int]
    scope_count: int

    def __repr__(self) -> str:
        return (
            f"_TokenCacheEntry(token_type={self.token_type!r}, expires_in={self.expires_in!r}, "
            f"scope_count={self.scope_count!r}, access_token='***')"
        )


@dataclass(frozen=True)
class PayPalOAuthCheckResult:
    """Non-sensitive connectivity outcome containing zero secrets or access tokens."""

    authenticated: bool
    status_code: Optional[int]
    base_url: str
    token_received: bool
    token_type: Optional[str]
    expires_in: Optional[int]
    scope_count: int
    error_code: Optional[str]
    message: str


@dataclass(frozen=True)
class PayPalCreatedOrder:
    """Sanitized order creation output returned by PayPal Orders v2."""

    paypal_order_id: str
    status: str
    intent: str
    amount: Decimal
    currency: str
    approval_url: Optional[str]


@dataclass(frozen=True)
class PayPalCaptureRecord:
    """Sanitized capture object extracted from a PayPal Orders v2 response."""

    capture_id: str
    status: str
    amount: Optional[Decimal]
    currency: Optional[str]


@dataclass(frozen=True)
class PayPalOrderSnapshot:
    """Validated PayPal Orders v2 order/capture state used during capture orchestration."""

    paypal_order_id: str
    status: str
    intent: str
    amount: Optional[Decimal]
    currency: Optional[str]
    payer_id: Optional[str]
    capture: Optional[PayPalCaptureRecord]


def _validate_sandbox_base_url(raw_url: str) -> str:
    """Ensures PAYPAL_BASE_URL is HTTPS and targets a PayPal Sandbox host."""
    cleaned = raw_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme != "https" or not hostname:
        raise PayPalConfigurationError(
            "PAYPAL_BASE_URL must be a valid https:// URL targeting PayPal Sandbox."
        )

    if hostname != ALLOWED_SANDBOX_HOST and not hostname.endswith(".sandbox.paypal.com"):
        raise PayPalConfigurationError(
            f"Refusing non-sandbox PAYPAL_BASE_URL host '{hostname}'. "
            f"Expected '{ALLOWED_SANDBOX_HOST}'."
        )

    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise PayPalConfigurationError(
            "PAYPAL_BASE_URL must contain only scheme and host (e.g. https://api-m.sandbox.paypal.com)."
        )

    return f"{parsed.scheme}://{parsed.netloc}"


def _validate_sandbox_link_url(raw_href: Any) -> Optional[str]:
    """Validates checkout/approval HATEOAS URLs strictly for HTTPS + PayPal Sandbox domain."""
    if not isinstance(raw_href, str):
        return None
    cleaned = raw_href.strip()
    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname:
        return None
    if hostname != "sandbox.paypal.com" and not hostname.endswith(".sandbox.paypal.com"):
        return None
    return cleaned


def _parse_allowed_redirect_hosts(raw_hosts: str) -> frozenset[str]:
    hosts: set[str] = set()
    for token in raw_hosts.split(","):
        cleaned = token.strip().lower().rstrip(".")
        if cleaned:
            hosts.add(cleaned)
    return frozenset(hosts)


def validate_paypal_redirect_url(
    raw_url: str,
    *,
    field_name: str = "redirect_url",
    allowed_hosts: Optional[frozenset[str]] = None,
) -> str:
    """
    Validates PayPal experience_context redirect URLs strictly:
    - Rejects empty strings, whitespace/control chars, >2048 length, and URL credentials.
    - Allows http:// ONLY for localhost / 127.0.0.1 development targets.
    - Requires https:// for all other hosts and blocks private/internal/raw IP redirects.
    - Enforces allowed_hosts allowlist when supplied (blocking arbitrary open redirects).
    """
    if not isinstance(raw_url, str):
        raise ValueError(f"{field_name} must be a valid URL string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be blank.")
    if len(cleaned) > 2048:
        raise ValueError(f"{field_name} exceeds maximum URL length of 2048 characters.")
    if any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
        raise ValueError(f"{field_name} must not contain whitespace or control characters.")

    parsed = urlparse(cleaned)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} contains an invalid port number.") from exc

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError(f"{field_name} must not embed URL credentials.")

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError(f"{field_name} must be a valid http(s) URL with a hostname.")

    if scheme == "http" and hostname not in ALLOWED_LOCAL_DEV_HOSTS:
        raise ValueError(
            f"{field_name} must use https:// for non-localhost hosts (http:// is restricted to localhost)."
        )

    is_ip_literal = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if hostname != "127.0.0.1":
            raise ValueError(f"{field_name} cannot target raw non-loopback IP addresses.")
    elif hostname != "localhost":
        if "." not in hostname or hostname.endswith(".local") or hostname.endswith(".internal"):
            raise ValueError(f"{field_name} must use a valid public DNS hostname.")

    if allowed_hosts is not None and hostname not in allowed_hosts:
        raise ValueError(
            f"{field_name} host '{hostname}' is not in the allowed PayPal redirect hosts."
        )

    return cleaned


def _read_env_setting(
    key: str,
    *,
    file_values: Mapping[str, Optional[str]],
    env_lookup: Mapping[str, str],
    prefer_environ_only: bool,
) -> str:
    if prefer_environ_only:
        raw = env_lookup.get(key)
    else:
        raw = file_values.get(key) or env_lookup.get(key)
    return raw.strip() if isinstance(raw, str) else ""


def get_allowed_paypal_redirect_hosts(
    env_path: Optional[Path] = DEFAULT_ENV_PATH,
    environ: Optional[Mapping[str, str]] = None,
) -> frozenset[str]:
    """
    Resolves permitted redirect hostnames (always allowing local development hosts
    plus hosts configured via PAYPAL_RETURN_URL, PAYPAL_CANCEL_URL, or
    PAYPAL_ALLOWED_REDIRECT_HOSTS). Does not require OAuth secrets to be present.
    """
    file_values: dict[str, Optional[str]] = {}
    if env_path is not None and env_path.is_file():
        file_values = dotenv_values(env_path)

    env_lookup = environ if environ is not None else os.environ
    prefer_environ_only = environ is not None

    hosts: set[str] = set(ALLOWED_LOCAL_DEV_HOSTS)
    raw_allowlist = _read_env_setting(
        "PAYPAL_ALLOWED_REDIRECT_HOSTS",
        file_values=file_values,
        env_lookup=env_lookup,
        prefer_environ_only=prefer_environ_only,
    )
    hosts.update(_parse_allowed_redirect_hosts(raw_allowlist))

    for key in ("PAYPAL_RETURN_URL", "PAYPAL_CANCEL_URL"):
        candidate = _read_env_setting(
            key,
            file_values=file_values,
            env_lookup=env_lookup,
            prefer_environ_only=prefer_environ_only,
        )
        if candidate:
            parsed_host = (urlparse(candidate).hostname or "").lower().rstrip(".")
            if parsed_host:
                hosts.add(parsed_host)

    return frozenset(hosts)


def load_paypal_sandbox_config(
    env_path: Optional[Path] = DEFAULT_ENV_PATH,
    environ: Optional[Mapping[str, str]] = None,
) -> PayPalSandboxConfig:
    """
    Loads PayPal Sandbox configuration cleanly from `backend/.env` (or explicit
    mapping in unit tests) without emitting secret values in exceptions.
    """
    file_values: dict[str, Optional[str]] = {}
    if env_path is not None and env_path.is_file():
        file_values = dotenv_values(env_path)

    env_lookup = environ if environ is not None else os.environ
    prefer_environ_only = environ is not None

    def _read_setting(key: str) -> str:
        return _read_env_setting(
            key,
            file_values=file_values,
            env_lookup=env_lookup,
            prefer_environ_only=prefer_environ_only,
        )

    missing: list[str] = []
    client_id = _read_setting("PAYPAL_CLIENT_ID")
    client_secret = _read_setting("PAYPAL_CLIENT_SECRET")
    raw_base_url = _read_setting("PAYPAL_BASE_URL")

    if not client_id:
        missing.append("PAYPAL_CLIENT_ID")
    if not client_secret:
        missing.append("PAYPAL_CLIENT_SECRET")
    if not raw_base_url:
        missing.append("PAYPAL_BASE_URL")

    if missing:
        raise PayPalConfigurationError(
            f"Missing required PayPal Sandbox variable(s) in backend/.env: {', '.join(missing)}."
        )

    base_url = _validate_sandbox_base_url(raw_base_url)

    explicit_hosts = _parse_allowed_redirect_hosts(_read_setting("PAYPAL_ALLOWED_REDIRECT_HOSTS"))
    config_allowlist = (
        frozenset(ALLOWED_LOCAL_DEV_HOSTS | explicit_hosts)
        if explicit_hosts
        else None
    )

    raw_return_url = _read_setting("PAYPAL_RETURN_URL") or DEFAULT_PAYPAL_RETURN_URL
    raw_cancel_url = _read_setting("PAYPAL_CANCEL_URL") or DEFAULT_PAYPAL_CANCEL_URL

    try:
        validated_return_url = validate_paypal_redirect_url(
            raw_return_url,
            field_name="PAYPAL_RETURN_URL",
            allowed_hosts=config_allowlist,
        )
        validated_cancel_url = validate_paypal_redirect_url(
            raw_cancel_url,
            field_name="PAYPAL_CANCEL_URL",
            allowed_hosts=config_allowlist,
        )
    except ValueError as exc:
        raise PayPalConfigurationError(str(exc)) from exc

    allowed_redirect_hosts: set[str] = set(ALLOWED_LOCAL_DEV_HOSTS) | set(explicit_hosts)
    for url_val in (validated_return_url, validated_cancel_url):
        host = (urlparse(url_val).hostname or "").lower().rstrip(".")
        if host:
            allowed_redirect_hosts.add(host)

    return PayPalSandboxConfig(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        return_url=validated_return_url,
        cancel_url=validated_cancel_url,
        allowed_redirect_hosts=frozenset(allowed_redirect_hosts),
    )


def _extract_safe_error_code(response: httpx.Response) -> str:
    """Extracts only a short error identifier from PayPal JSON responses, never secrets or raw bodies."""
    fallback = f"http_{response.status_code}"
    try:
        payload: Any = response.json()
    except ValueError:
        return fallback

    if not isinstance(payload, dict):
        return fallback

    raw_error = payload.get("error") or payload.get("name")
    if not isinstance(raw_error, str):
        return fallback

    safe_token = "".join(ch for ch in raw_error.strip() if ch.isalnum() or ch in "_-")
    return safe_token[:64] or fallback


def _parse_decimal_amount(raw_value: Any) -> Optional[Decimal]:
    if raw_value is None or isinstance(raw_value, bool):
        return None
    try:
        dec = Decimal(str(raw_value).strip())
        if not dec.is_finite():
            return None
        return dec.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return None


def _extract_pu_amount_and_capture(payload: Mapping[str, Any]) -> tuple[
    Optional[Decimal],
    Optional[str],
    Optional[PayPalCaptureRecord],
]:
    purchase_units = payload.get("purchase_units")
    if not isinstance(purchase_units, list) or not purchase_units:
        return None, None, None

    first_pu = purchase_units[0]
    if not isinstance(first_pu, dict):
        return None, None, None

    amt_obj = first_pu.get("amount")
    pu_amount: Optional[Decimal] = None
    pu_currency: Optional[str] = None
    if isinstance(amt_obj, dict):
        pu_amount = _parse_decimal_amount(amt_obj.get("value"))
        raw_curr = amt_obj.get("currency_code")
        if isinstance(raw_curr, str) and raw_curr.strip():
            pu_currency = raw_curr.strip().upper()

    capture_record: Optional[PayPalCaptureRecord] = None
    payments_obj = first_pu.get("payments")
    if isinstance(payments_obj, dict):
        captures = payments_obj.get("captures")
        if isinstance(captures, list) and captures:
            first_cap = captures[0]
            if isinstance(first_cap, dict):
                cap_id = first_cap.get("id")
                cap_status = first_cap.get("status")
                cap_amt_obj = first_cap.get("amount")
                cap_amt: Optional[Decimal] = None
                cap_curr: Optional[str] = None
                if isinstance(cap_amt_obj, dict):
                    cap_amt = _parse_decimal_amount(cap_amt_obj.get("value"))
                    raw_c_curr = cap_amt_obj.get("currency_code")
                    if isinstance(raw_c_curr, str) and raw_c_curr.strip():
                        cap_curr = raw_c_curr.strip().upper()
                if isinstance(cap_id, str) and cap_id.strip() and isinstance(cap_status, str) and cap_status.strip():
                    capture_record = PayPalCaptureRecord(
                        capture_id=cap_id.strip(),
                        status=cap_status.strip().upper(),
                        amount=cap_amt,
                        currency=cap_curr,
                    )

    return pu_amount, pu_currency, capture_record


def _extract_safe_payer_id(payload: Mapping[str, Any]) -> Optional[str]:
    payer = payload.get("payer")
    if not isinstance(payer, dict):
        return None
    raw_id = payer.get("payer_id")
    if not isinstance(raw_id, str):
        return None
    clean = "".join(ch for ch in raw_id.strip() if ch.isalnum() or ch in "_-")
    return clean[:64] or None


class PayPalSandboxClient:
    """
    Thread-safe PayPal Sandbox API client maintaining an in-memory OAuth Bearer
    token cache with automatic expiry-buffer refresh and zero disk/DB token storage.
    """

    def __init__(
        self,
        *,
        env_path: Optional[Path] = DEFAULT_ENV_PATH,
        environ: Optional[Mapping[str, str]] = None,
        transport: Optional[httpx.BaseTransport] = None,
        timeout_seconds: float = 15.0,
        expiry_skew_seconds: float = DEFAULT_EXPIRY_SKEW_SECONDS,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._env_path = env_path
        self._environ = environ
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._expiry_skew_seconds = max(0.0, float(expiry_skew_seconds))
        self._monotonic = monotonic_fn
        self._lock = threading.Lock()
        self._cached_entry: Optional[_TokenCacheEntry] = None

    def _compute_expiry_deadline(self, expires_in: Optional[int], now: float) -> float:
        if expires_in is None or expires_in <= 0:
            return now + 1.0
        if expires_in > self._expiry_skew_seconds:
            effective_ttl = float(expires_in) - self._expiry_skew_seconds
        else:
            # Guard short TTLs cleanly while still refreshing shortly before nominal expiry
            effective_ttl = max(0.5, float(expires_in) * 0.8)
        return now + effective_ttl

    def clear_cached_token(self) -> None:
        """Clears any cached OAuth token from memory."""
        with self._lock:
            self._cached_entry = None

    def get_cache_debug_state(self) -> dict[str, Any]:
        """Returns non-sensitive token cache status for diagnostics/tests (never token text)."""
        with self._lock:
            if self._cached_entry is None:
                return {"has_token": False, "expires_in": None, "scope_count": 0}
            now = self._monotonic()
            return {
                "has_token": True,
                "valid": now < self._cached_entry.expires_at_monotonic,
                "expires_in": self._cached_entry.expires_in,
                "scope_count": self._cached_entry.scope_count,
            }

    def _request_new_token(self, config: PayPalSandboxConfig) -> tuple[_TokenCacheEntry, int]:
        token_url = f"{config.base_url}{OAUTH_TOKEN_PATH}"

        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.post(
                    token_url,
                    auth=httpx.BasicAuth(config.client_id, config.client_secret),
                    headers={
                        "Accept": "application/json",
                        "Accept-Language": "en_US",
                    },
                    data={"grant_type": "client_credentials"},
                )
        except httpx.TimeoutException as exc:
            raise PayPalAPIError(
                status_code=504,
                error_code="timeout",
                message=f"Timed out after {self._timeout_seconds:.0f}s connecting to PayPal Sandbox OAuth endpoint.",
            ) from exc
        except httpx.RequestError as exc:
            raise PayPalAPIError(
                status_code=503,
                error_code=type(exc).__name__,
                message="Network or TLS connection error while contacting PayPal Sandbox OAuth endpoint.",
            ) from exc

        if response.status_code != httpx.codes.OK:
            safe_code = _extract_safe_error_code(response)
            if response.status_code in (401, 403):
                raise PayPalAPIError(
                    status_code=502,
                    error_code=safe_code,
                    message=(
                        f"PayPal Sandbox authentication failed (HTTP {response.status_code}, "
                        f"error='{safe_code}'): verify PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET."
                    ),
                )
            raise PayPalAPIError(
                status_code=502,
                error_code=safe_code,
                message=f"PayPal Sandbox OAuth request failed with HTTP {response.status_code} (error='{safe_code}').",
            )

        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise PayPalAPIError(
                status_code=502,
                error_code="invalid_json",
                message="PayPal Sandbox returned HTTP 200 with a non-JSON OAuth response payload.",
            ) from exc

        if not isinstance(payload, dict):
            raise PayPalAPIError(
                status_code=502,
                error_code="invalid_payload",
                message="PayPal Sandbox OAuth response payload had an unexpected structure.",
            )

        raw_token = payload.get("access_token")
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise PayPalAPIError(
                status_code=502,
                error_code="missing_access_token",
                message="PayPal Sandbox returned HTTP 200 without an access token.",
            )

        raw_type = payload.get("token_type")
        token_type = raw_type.strip() if isinstance(raw_type, str) and raw_type.strip() else None

        raw_expires = payload.get("expires_in")
        expires_in = (
            int(raw_expires)
            if isinstance(raw_expires, int) and not isinstance(raw_expires, bool)
            else None
        )

        raw_scope = payload.get("scope")
        scope_count = len(raw_scope.split()) if isinstance(raw_scope, str) and raw_scope.strip() else 0

        now = self._monotonic()
        entry = _TokenCacheEntry(
            access_token=raw_token.strip(),
            expires_at_monotonic=self._compute_expiry_deadline(expires_in, now),
            token_type=token_type,
            expires_in=expires_in,
            scope_count=scope_count,
        )
        return entry, int(response.status_code)

    def _get_or_refresh_token_entry(
        self,
        config: PayPalSandboxConfig,
        *,
        force_refresh: bool = False,
    ) -> _TokenCacheEntry:
        with self._lock:
            now = self._monotonic()
            if (
                not force_refresh
                and self._cached_entry is not None
                and now < self._cached_entry.expires_at_monotonic
            ):
                return self._cached_entry

            entry, _ = self._request_new_token(config)
            self._cached_entry = entry
            return entry

    def check_oauth_connectivity(self) -> PayPalOAuthCheckResult:
        """
        Tests live Sandbox OAuth credentials directly without returning secrets or tokens.
        """
        try:
            config = load_paypal_sandbox_config(env_path=self._env_path, environ=self._environ)
        except PayPalConfigurationError as exc:
            return PayPalOAuthCheckResult(
                authenticated=False,
                status_code=None,
                base_url="(unconfigured)",
                token_received=False,
                token_type=None,
                expires_in=None,
                scope_count=0,
                error_code="configuration_error",
                message=str(exc),
            )

        try:
            entry, http_status = self._request_new_token(config)
        except PayPalAPIError as exc:
            mapped_status: Optional[int] = None
            if exc.error_code == "invalid_client":
                mapped_status = 401
            elif exc.error_code.startswith("http_") and exc.error_code[5:].isdigit():
                mapped_status = int(exc.error_code[5:])
            elif exc.error_code in {"invalid_json", "invalid_payload", "missing_access_token"}:
                mapped_status = 200
            return PayPalOAuthCheckResult(
                authenticated=False,
                status_code=mapped_status,
                base_url=config.base_url,
                token_received=False,
                token_type=None,
                expires_in=None,
                scope_count=0,
                error_code=exc.error_code,
                message=exc.message,
            )

        with self._lock:
            self._cached_entry = entry

        return PayPalOAuthCheckResult(
            authenticated=True,
            status_code=http_status,
            base_url=config.base_url,
            token_received=True,
            token_type=entry.token_type,
            expires_in=entry.expires_in,
            scope_count=entry.scope_count,
            error_code=None,
            message="PayPal Sandbox OAuth authentication succeeded and issued an access token.",
        )

    def _authorized_json_request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, dict[str, Any]]:
        config = load_paypal_sandbox_config(env_path=self._env_path, environ=self._environ)
        url = f"{config.base_url}{path}"

        for attempt in range(2):
            entry = self._get_or_refresh_token_entry(config, force_refresh=(attempt > 0))
            headers: dict[str, str] = {
                "Authorization": f"Bearer {entry.access_token}",
                "Accept": "application/json",
            }
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            if extra_headers:
                headers.update(extra_headers)

            try:
                with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                    response = client.request(method=method, url=url, headers=headers, json=json_body)
            except httpx.TimeoutException as exc:
                raise PayPalAPIError(
                    status_code=504,
                    error_code="timeout",
                    message=f"Timed out after {self._timeout_seconds:.0f}s waiting for PayPal Sandbox API.",
                ) from exc
            except httpx.RequestError as exc:
                raise PayPalAPIError(
                    status_code=503,
                    error_code=type(exc).__name__,
                    message="Network or TLS connection error while communicating with PayPal Sandbox API.",
                ) from exc

            if response.status_code == 401 and attempt == 0:
                self.clear_cached_token()
                continue

            if response.status_code >= 400:
                safe_code = _extract_safe_error_code(response)
                client_status = 422 if 400 <= response.status_code < 500 else 502
                if response.status_code == 404:
                    client_status = 404
                raise PayPalAPIError(
                    status_code=client_status,
                    error_code=safe_code,
                    message=(
                        f"PayPal Sandbox rejected the Orders API request (HTTP {response.status_code}, "
                        f"error='{safe_code}')."
                    ),
                )

            try:
                parsed: Any = response.json()
            except ValueError as exc:
                raise PayPalAPIError(
                    status_code=502,
                    error_code="invalid_json",
                    message="PayPal Sandbox returned a non-JSON Orders API response.",
                ) from exc

            if not isinstance(parsed, dict):
                raise PayPalAPIError(
                    status_code=502,
                    error_code="invalid_payload",
                    message="PayPal Sandbox returned an unexpected JSON structure.",
                )

            return int(response.status_code), parsed

        raise PayPalAPIError(
            status_code=502,
            error_code="auth_retry_exhausted",
            message="PayPal Sandbox rejected refreshed OAuth token authorization.",
        )

    def create_order(
        self,
        *,
        amount: Decimal,
        currency: str,
        internal_reference: str,
        return_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
    ) -> PayPalCreatedOrder:
        """
        Creates a PayPal Orders v2 order (`intent=CAPTURE`) using `PayPal-Request-Id`
        idempotency and modern `payment_source.paypal.experience_context` redirect URLs.
        """
        config = load_paypal_sandbox_config(env_path=self._env_path, environ=self._environ)

        norm_amount = amount.quantize(Decimal("0.01"))
        norm_currency = currency.strip().upper()
        if norm_currency not in SUPPORTED_PAYPAL_CURRENCIES:
            raise PayPalAPIError(
                status_code=422,
                error_code="unsupported_currency",
                message=f"Unsupported PayPal Sandbox currency '{norm_currency}'.",
            )

        try:
            resolved_return_url = (
                validate_paypal_redirect_url(
                    return_url,
                    field_name="return_url",
                    allowed_hosts=config.allowed_redirect_hosts,
                )
                if return_url is not None
                else config.return_url
            )
            resolved_cancel_url = (
                validate_paypal_redirect_url(
                    cancel_url,
                    field_name="cancel_url",
                    allowed_hosts=config.allowed_redirect_hosts,
                )
                if cancel_url is not None
                else config.cancel_url
            )
        except ValueError as exc:
            raise PayPalAPIError(
                status_code=422,
                error_code="invalid_redirect_url",
                message=str(exc),
            ) from exc

        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": internal_reference,
                    "custom_id": internal_reference,
                    "description": "FraudTrace AI Sandbox Payment Evaluation",
                    "amount": {
                        "currency_code": norm_currency,
                        "value": f"{norm_amount:.2f}",
                    },
                }
            ],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "shipping_preference": "NO_SHIPPING",
                        "user_action": "PAY_NOW",
                        "return_url": resolved_return_url,
                        "cancel_url": resolved_cancel_url,
                    }
                }
            },
        }

        _, payload = self._authorized_json_request(
            "POST",
            ORDERS_V2_PATH,
            json_body=body,
            extra_headers={"PayPal-Request-Id": internal_reference},
        )

        order_id = payload.get("id")
        raw_status = payload.get("status")
        raw_intent = payload.get("intent", "CAPTURE")

        if not isinstance(order_id, str) or not order_id.strip():
            raise PayPalAPIError(
                status_code=502,
                error_code="missing_order_id",
                message="PayPal Sandbox response omitted the created order ID.",
            )
        if not isinstance(raw_status, str) or not raw_status.strip():
            raise PayPalAPIError(
                status_code=502,
                error_code="missing_order_status",
                message="PayPal Sandbox response omitted the created order status.",
            )
        if str(raw_intent).strip().upper() != "CAPTURE":
            raise PayPalAPIError(
                status_code=502,
                error_code="unexpected_intent",
                message="PayPal Sandbox returned an order with an unexpected intent.",
            )

        pu_amount, pu_currency, _ = _extract_pu_amount_and_capture(payload)
        if pu_amount is not None and pu_amount != norm_amount:
            raise PayPalAPIError(
                status_code=502,
                error_code="amount_mismatch",
                message="PayPal Sandbox returned an order amount different from the validated request.",
            )
        if pu_currency is not None and pu_currency != norm_currency:
            raise PayPalAPIError(
                status_code=502,
                error_code="currency_mismatch",
                message="PayPal Sandbox returned an order currency different from the validated request.",
            )

        approval_url: Optional[str] = None
        links = payload.get("links")
        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict):
                    continue
                rel = str(link.get("rel", "")).strip().lower()
                if rel in {"approve", "payer-action"}:
                    validated_href = _validate_sandbox_link_url(link.get("href"))
                    if validated_href:
                        approval_url = validated_href
                        break

        return PayPalCreatedOrder(
            paypal_order_id=order_id.strip(),
            status=raw_status.strip().upper(),
            intent="CAPTURE",
            amount=norm_amount,
            currency=norm_currency,
            approval_url=approval_url,
        )

    def get_order(self, paypal_order_id: str) -> PayPalOrderSnapshot:
        """Retrieves authoritative PayPal Orders v2 order details before capture."""
        safe_id = paypal_order_id.strip()
        encoded_id = quote(safe_id, safe="")
        _, payload = self._authorized_json_request("GET", f"{ORDERS_V2_PATH}/{encoded_id}")
        return self._parse_order_snapshot(expected_order_id=safe_id, payload=payload)

    def capture_order(
        self,
        paypal_order_id: str,
        *,
        idempotency_key: str,
    ) -> PayPalOrderSnapshot:
        """Captures an approved PayPal Orders v2 order idempotently and validates response."""
        safe_id = paypal_order_id.strip()
        encoded_id = quote(safe_id, safe="")
        _, payload = self._authorized_json_request(
            "POST",
            f"{ORDERS_V2_PATH}/{encoded_id}/capture",
            json_body={},
            extra_headers={"PayPal-Request-Id": idempotency_key},
        )
        return self._parse_order_snapshot(expected_order_id=safe_id, payload=payload)

    def _parse_order_snapshot(
        self,
        *,
        expected_order_id: str,
        payload: Mapping[str, Any],
    ) -> PayPalOrderSnapshot:
        returned_id = payload.get("id")
        if not isinstance(returned_id, str) or returned_id.strip() != expected_order_id:
            raise PayPalAPIError(
                status_code=502,
                error_code="order_id_mismatch",
                message="PayPal Sandbox returned an order ID that does not match the requested order.",
            )

        raw_status = payload.get("status")
        if not isinstance(raw_status, str) or not raw_status.strip():
            raise PayPalAPIError(
                status_code=502,
                error_code="missing_order_status",
                message="PayPal Sandbox response omitted the order status.",
            )

        raw_intent = str(payload.get("intent", "CAPTURE")).strip().upper()
        pu_amount, pu_currency, capture_rec = _extract_pu_amount_and_capture(payload)
        payer_id = _extract_safe_payer_id(payload)

        return PayPalOrderSnapshot(
            paypal_order_id=returned_id.strip(),
            status=raw_status.strip().upper(),
            intent=raw_intent,
            amount=pu_amount,
            currency=pu_currency,
            payer_id=payer_id,
            capture=capture_rec,
        )


_default_client_lock = threading.Lock()
_default_client: Optional[PayPalSandboxClient] = None


def get_paypal_client() -> PayPalSandboxClient:
    """FastAPI dependency returning the process-wide thread-safe PayPal Sandbox client."""
    global _default_client
    with _default_client_lock:
        if _default_client is None:
            _default_client = PayPalSandboxClient()
        return _default_client


def verify_paypal_sandbox_oauth(
    *,
    env_path: Optional[Path] = DEFAULT_ENV_PATH,
    environ: Optional[Mapping[str, str]] = None,
    transport: Optional[httpx.BaseTransport] = None,
    timeout_seconds: float = 15.0,
) -> PayPalOAuthCheckResult:
    """Preserved connectivity test helper delegating safely to PayPalSandboxClient."""
    client = PayPalSandboxClient(
        env_path=env_path,
        environ=environ,
        transport=transport,
        timeout_seconds=timeout_seconds,
    )
    return client.check_oauth_connectivity()
