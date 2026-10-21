"""OpenAI-compatible model provider.

The platform talks to *any* endpoint that implements the OpenAI
``/v1/chat/completions`` contract.  Nothing about a specific vendor is
hard-coded: the base URL, model id, credentials, headers and generation
parameters are all configuration.

Two compatibility problems are handled explicitly because not every
"OpenAI-compatible" endpoint behaves identically:

``native tool calling``
    Some compatible servers implement ``tools``/``tool_calls``; others
    reject the parameter or ignore it.  :meth:`Provider.supports_native_tools`
    probes for support and the runtime falls back to
    :mod:`b_hunters.platform.agents.compat` which asks the model to emit a
    JSON tool call in its message content and validates it against the very
    same JSON schema and permission checks.

``structured outputs``
    ``response_format={"type": "json_schema"}`` is only offered to servers
    that advertise support.  Otherwise the runtime asks for JSON in the
    prompt and parses it defensively.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from ..security.redact import redact_headers, redact_text

log = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "b-hunters-platform/1.0"


class ProviderError(Exception):
    """Base class for provider failures."""

    def __init__(self, message: str, *, status_code: int = 0, retryable: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


class ProviderTimeout(ProviderError):
    def __init__(self, message: str = "model request timed out") -> None:
        super().__init__(message, retryable=True)


class ProviderUnavailable(ProviderError):
    def __init__(self, message: str, *, status_code: int = 0) -> None:
        super().__init__(message, status_code=status_code, retryable=True)


class ProviderAuthError(ProviderError):
    def __init__(self, message: str = "provider rejected the credentials") -> None:
        super().__init__(message, status_code=401, retryable=False)


class ProviderInvalidResponse(ProviderError):
    def __init__(self, message: str = "provider returned an unusable response") -> None:
        super().__init__(message, retryable=False)


@dataclass
class ToolSpec:
    """JSON-schema description of a tool, shared by native and compat modes."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    required: Sequence[str] = ()

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]
    #: ``"native"`` when the server produced a tool call, ``"compat"`` when
    #: the platform parsed it out of a plain message.
    origin: str = "native"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "origin": self.origin,
        }


@dataclass
class ChatMessage:
    """A single chat message."""

    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""

    def to_openai(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments, ensure_ascii=False),
                    },
                }
                for call in self.tool_calls
            ]
        if self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        if self.name:
            payload["name"] = self.name
        return payload


@dataclass
class Completion:
    """The result of a chat completion."""

    message: ChatMessage
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def estimated_cost(self) -> float:
        """Cost estimate in USD.

        Only meaningful when the configured provider exposes pricing; the
        platform stores the configured price per million tokens when known
        and otherwise reports ``0.0`` rather than guessing.
        """
        return 0.0


@dataclass
class ProviderConfig:
    """Everything needed to talk to one OpenAI-compatible endpoint."""

    name: str = "default"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    #: Optional per-role model overrides.
    role_models: dict[str, str] = field(default_factory=dict)
    temperature: float = 0.0
    top_p: float = 1.0
    max_output_tokens: int = 4096
    max_context_tokens: int = 128000
    timeout_seconds: float = 120.0
    max_retries: int = 2
    retry_backoff_seconds: float = 1.5
    concurrency: int = 4
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra_body: dict[str, Any] = field(default_factory=dict)
    #: Price per 1M prompt tokens in USD, used for cost estimation.
    price_per_million_prompt: float = 0.0
    price_per_million_completion: float = 0.0
    enabled: bool = True

    def model_for_role(self, role: str) -> str:
        return self.role_models.get(role) or self.model

    def chat_url(self) -> str:
        base = (self.base_url or "").rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def models_url(self) -> str:
        base = (self.base_url or "").rstrip("/")
        if base.endswith("/models"):
            return base
        return f"{base}/models"


class Provider:
    """An OpenAI-compatible chat-completions client."""

    def __init__(self, config: ProviderConfig, *, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client
        self._owns_client = client is None
        self._native_tools: Optional[bool] = None
        self._models_cache: Optional[list[str]] = None
        self._last_error = ""
        self._last_success_at: Optional[float] = None
        self._call_count = 0
        self._error_count = 0
        self._token_usage = {"prompt": 0, "completion": 0, "total": 0}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> Provider:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=max(4, self.config.concurrency * 2)),
            )
            self._owns_client = True
        return self._client

    # ------------------------------------------------------------------
    # Health / capability probing
    # ------------------------------------------------------------------
    async def health_check(self) -> dict[str, Any]:
        """Check connectivity and whether the configured model exists."""
        started = time.monotonic()
        result: dict[str, Any] = {
            "name": self.config.name,
            "base_url": self.config.base_url,
            "model": self.config.model,
            "reachable": False,
            "model_available": False,
            "native_tools": bool(self._native_tools),
            "models": [],
            "error": "",
            "latency_ms": 0,
        }
        try:
            models = await self.list_models()
            result["reachable"] = True
            result["models"] = models[:50]
            if self.config.model:
                result["model_available"] = self.config.model in models
            else:
                result["model_available"] = bool(models)
        except ProviderError as exc:
            result["error"] = exc.message
        except Exception as exc:  # pragma: no cover - defensive
            result["error"] = f"{type(exc).__name__}: {exc}"
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return result

    async def list_models(self) -> list[str]:
        if self._models_cache is not None:
            return self._models_cache
        client = self._get_client()
        try:
            response = await client.get(
                self.config.models_url(),
                headers=self._headers(),
                timeout=min(self.config.timeout_seconds, 30.0),
            )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout(f"listing models timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"cannot reach provider: {exc}") from exc

        if response.status_code >= 400:
            raise ProviderError(
                f"provider returned HTTP {response.status_code} for /models",
                status_code=response.status_code,
                retryable=response.status_code >= 500,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderInvalidResponse("provider /models response was not JSON") from exc

        entries = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            # Some servers expose a flat list of ids.
            entries = payload.get("models") if isinstance(payload, dict) else None
        models: list[str] = []
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, str):
                    models.append(entry)
                elif isinstance(entry, dict):
                    identifier = entry.get("id") or entry.get("name")
                    if identifier:
                        models.append(str(identifier))
        self._models_cache = sorted(set(models))
        return self._models_cache

    async def supports_native_tools(self) -> bool:
        """Probe whether the endpoint honours the ``tools`` parameter.

        The probe is cheap: one minimal completion that asks for a tool call.
        Servers that ignore ``tools`` simply return a plain message, which is
        detected and cached.
        """
        if self._native_tools is not None:
            return self._native_tools
        spec = ToolSpec(
            name="probe",
            description="Probe tool used to detect native tool calling support.",
            parameters={"type": "object", "properties": {}},
        )
        try:
            completion = await self.complete(
                messages=[{"role": "user", "content": "Call the probe tool with no arguments."}],
                tools=[spec],
                max_tokens=64,
                timeout=min(self.config.timeout_seconds, 45.0),
            )
        except ProviderError:
            self._native_tools = False
            return False
        self._native_tools = bool(completion.message.tool_calls)
        return self._native_tools

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": DEFAULT_USER_AGENT,
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers.update(self.config.extra_headers or {})
        return headers

    def _body(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: Sequence[ToolSpec],
        model: str,
        temperature: Optional[float],
        max_tokens: Optional[int],
        response_format: Optional[str],
        stream: bool,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "stream": stream,
        }
        if temperature is not None:
            body["temperature"] = temperature
        if max_tokens:
            body["max_tokens"] = max_tokens
        if tools and self._native_tools is not False:
            body["tools"] = [spec.to_openai() for spec in tools]
            body["tool_choice"] = "auto"
        if response_format == "json_object":
            body["response_format"] = {"type": "json_object"}
        elif response_format == "json_schema" and self._native_tools is not False:
            body["response_format"] = {"type": "json_schema"}
        body.update(self.config.extra_body or {})
        return body

    async def complete(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: Sequence[ToolSpec] = (),
        model: str = "",
        role: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Completion:
        """Perform one chat completion with retries."""
        resolved_model = model or self.config.model_for_role(role) or self.config.model
        if not resolved_model:
            raise ProviderError("no model configured for this provider")
        body = self._body(
            messages,
            tools=tools,
            model=resolved_model,
            temperature=self.config.temperature if temperature is None else temperature,
            max_tokens=max_tokens or self.config.max_output_tokens,
            response_format=response_format,
            stream=False,
        )
        return await self._request_with_retry(body, timeout=timeout)

    async def _request_with_retry(self, body: dict[str, Any], *, timeout: Optional[float]) -> Completion:
        attempts = max(1, self.config.max_retries + 1)
        last_error: Optional[ProviderError] = None
        for attempt in range(1, attempts + 1):
            try:
                return await self._request(body, timeout=timeout)
            except ProviderError as exc:
                last_error = exc
                self._error_count += 1
                self._last_error = exc.message
                if not exc.retryable or attempt >= attempts:
                    raise
                delay = self.config.retry_backoff_seconds * (2 ** (attempt - 1))
                log.warning(
                    "provider request failed (attempt %s/%s): %s - retrying in %.1fs",
                    attempt,
                    attempts,
                    exc.message,
                    delay,
                )
                await _sleep(delay)
        raise last_error or ProviderError("provider request failed")

    async def _request(self, body: dict[str, Any], *, timeout: Optional[float]) -> Completion:
        client = self._get_client()
        request_timeout = httpx.Timeout(timeout or self.config.timeout_seconds)
        started = time.monotonic()
        try:
            response = await client.post(
                self.config.chat_url(),
                headers=self._headers(),
                json=body,
                timeout=request_timeout,
            )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout(
                f"model request timed out after {timeout or self.config.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"cannot reach model endpoint: {exc}") from exc

        latency_ms = int((time.monotonic() - started) * 1000)

        if response.status_code == 401 or response.status_code == 403:
            raise ProviderAuthError(f"provider rejected the credentials (HTTP {response.status_code})")
        if response.status_code == 404:
            raise ProviderError(
                f"model endpoint not found (HTTP 404): {self.config.chat_url()}",
                status_code=404,
                retryable=False,
            )
        if response.status_code == 429:
            raise ProviderError("provider rate limit reached (HTTP 429)", status_code=429, retryable=True)
        if response.status_code >= 500:
            raise ProviderError(
                f"provider error HTTP {response.status_code}: {redact_text(response.text[:400])}",
                status_code=response.status_code,
                retryable=True,
            )
        if response.status_code >= 400:
            raise ProviderError(
                f"provider rejected the request (HTTP {response.status_code}): "
                f"{redact_text(response.text[:400])}",
                status_code=response.status_code,
                retryable=False,
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderInvalidResponse("provider response was not valid JSON") from exc

        return self._parse(payload, latency_ms=latency_ms, raw_body=body)

    def _parse(self, payload: dict[str, Any], *, latency_ms: int, raw_body: dict[str, Any]) -> Completion:
        if not isinstance(payload, dict):
            raise ProviderInvalidResponse("provider response was not a JSON object")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderInvalidResponse("provider response contained no choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise ProviderInvalidResponse("provider response choice was malformed")

        message_payload = first.get("message")
        if not isinstance(message_payload, dict):
            raise ProviderInvalidResponse("provider response contained no message")

        content = message_payload.get("content")
        if content is None:
            content = ""
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)

        tool_calls: list[ToolCall] = []
        raw_calls = message_payload.get("tool_calls")
        if isinstance(raw_calls, list):
            for index, raw in enumerate(raw_calls):
                if not isinstance(raw, dict):
                    continue
                function = raw.get("function") or {}
                name = function.get("name") or ""
                arguments = function.get("arguments")
                if isinstance(arguments, str):
                    try:
                        parsed = json.loads(arguments) if arguments.strip() else {}
                    except ValueError:
                        parsed = {"_raw": arguments}
                elif isinstance(arguments, dict):
                    parsed = arguments
                else:
                    parsed = {}
                tool_calls.append(
                    ToolCall(
                        id=str(raw.get("id") or f"call_{index}"),
                        name=str(name),
                        arguments=parsed if isinstance(parsed, dict) else {"value": parsed},
                        origin="native",
                    )
                )

        usage = payload.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        total_tokens = int(usage.get("total_tokens") or (prompt_tokens + completion_tokens))

        self._call_count += 1
        self._last_success_at = time.time()
        self._token_usage["prompt"] += prompt_tokens
        self._token_usage["completion"] += completion_tokens
        self._token_usage["total"] += total_tokens

        return Completion(
            message=ChatMessage(role="assistant", content=content, tool_calls=tool_calls),
            model=str(payload.get("model") or raw_body.get("model") or ""),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            finish_reason=str(first.get("finish_reason") or ""),
            latency_ms=latency_ms,
            raw=payload,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def usage(self) -> dict[str, Any]:
        return {
            "calls": self._call_count,
            "errors": self._error_count,
            "prompt_tokens": self._token_usage["prompt"],
            "completion_tokens": self._token_usage["completion"],
            "total_tokens": self._token_usage["total"],
            "estimated_cost_usd": round(
                self._token_usage["prompt"] / 1_000_000 * self.config.price_per_million_prompt
                + self._token_usage["completion"] / 1_000_000 * self.config.price_per_million_completion,
                6,
            ),
            "last_error": self._last_error,
            "last_success_at": self._last_success_at,
        }

    def status(self) -> dict[str, Any]:
        return {
            "name": self.config.name,
            "base_url": self.config.base_url,
            "model": self.config.model,
            "enabled": self.config.enabled,
            "native_tools": bool(self._native_tools),
            "timeout_seconds": self.config.timeout_seconds,
            "max_retries": self.config.max_retries,
            "concurrency": self.config.concurrency,
            "headers": redact_headers(self.config.extra_headers),
            **self.usage(),
        }


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


def build_provider(config: ProviderConfig, *, client: httpx.AsyncClient | None = None) -> Provider:
    """Factory used by the dependency wiring."""
    return Provider(config, client=client)


def provider_config_from_env(prefix: str = "BHUNTERS_LLM_") -> ProviderConfig:
    """Build a provider configuration purely from environment variables.

    Used as the fallback when no provider has been configured in the admin
    UI.  Secrets are read from the environment so they never live in the
    database or in source control.
    """

    def _get(name: str, default: str = "") -> str:
        return os.environ.get(f"{prefix}{name}", default)

    base_url = _get("BASE_URL")
    if not base_url:
        return ProviderConfig(enabled=False)
    return ProviderConfig(
        name=_get("NAME", "default"),
        base_url=base_url,
        api_key=_get("API_KEY"),
        model=_get("MODEL"),
        temperature=float(_get("TEMPERATURE", "0") or 0),
        max_output_tokens=int(_get("MAX_OUTPUT_TOKENS", "4096") or 4096),
        max_context_tokens=int(_get("MAX_CONTEXT_TOKENS", "128000") or 128000),
        timeout_seconds=float(_get("TIMEOUT", "120") or 120),
        max_retries=int(_get("MAX_RETRIES", "2") or 2),
        concurrency=int(_get("CONCURRENCY", "4") or 4),
    )
