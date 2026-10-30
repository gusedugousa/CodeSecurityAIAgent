"""Secret redaction used before code/text reaches LLM prompts, logs, traces, or reports."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"

_SECRET_KEY_PATTERN = re.compile(r"(key|token|secret|password|passwd|credential)", re.IGNORECASE)

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{10,}=*"),
    re.compile(
        r"""(?ix)
        \b(api[_-]?key|access[_-]?key|secret|token|password|passwd)
        \s*[:=]\s*
        ['"]?([A-Za-z0-9/+_\-.]{8,})['"]?
        """
    ),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    for pattern in _PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: _redact_value(key, value) for key, value in data.items()}


def _redact_value(key: str, value: Any) -> Any:
    if _SECRET_KEY_PATTERN.search(key):
        if isinstance(value, str):
            return _REDACTED
        if value is not None:
            return _REDACTED
        return value
    if isinstance(value, dict):
        return redact_dict(value)
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value


class AuthContext:
    """Placeholder shape for an authenticated principal. See docs/extension_points.md."""

    def __init__(self, subject: str, claims: dict[str, Any] | None = None) -> None:
        self.subject = subject
        self.claims = claims or {}


class AuthenticationPlaceholder:
    def authenticate(self, request: Any) -> AuthContext:
        raise NotImplementedError(
            "TODO: wire real AuthN provider (OAuth/SSO) — see docs/extension_points.md"
        )


class AuthorizationPlaceholder:
    def authorize(self, context: AuthContext, resource: str, action: str) -> bool:
        raise NotImplementedError(
            "TODO: wire real AuthZ/RBAC policy engine — see docs/extension_points.md"
        )


class RateLimiterPlaceholder:
    def check(self, key: str) -> bool:
        raise NotImplementedError(
            "TODO: wire real rate limiter (e.g. Redis token bucket) — see docs/extension_points.md"
        )
