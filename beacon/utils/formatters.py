"""Formatting and sanitization helpers shared by Beacon interfaces."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Iterable, Optional


_BYTES_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;&]+"),
    re.compile(r"(?i)\b((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+=*"),
)


def format_bytes(value: int | float) -> str:
    """Format a byte count using a human-readable binary unit."""
    size = float(max(0, value))
    for unit in _BYTES_UNITS:
        if size < 1024 or unit == _BYTES_UNITS[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format a duration as a compact human-readable value."""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        minutes, remainder = divmod(seconds, 60)
        return f"{int(minutes)}m {remainder:.0f}s"
    hours, minutes, remainder = divmod(int(seconds), 3600)
    return f"{hours}h {minutes}m"


def format_timestamp(value: Optional[datetime]) -> str:
    """Format a timestamp consistently for terminal and web output."""
    if not value:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def format_int(value: Optional[int]) -> str:
    """Format an integer for polished terminal output."""
    return f"{int(value or 0):,}"


def redact_text(value: Any) -> str:
    """Redact common credential and token values while preserving context."""
    text = str(value or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\g<1>[REDACTED]", text)
    return text


def json_safe(value: Any) -> Any:
    """Convert nested analysis data into JSON-serializable primitives."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if hasattr(value, "to_dict"):
        return json_safe(value.to_dict())
    return value


def write_json(path: str, data: Any) -> None:
    """Write indented JSON to a file."""
    from pathlib import Path

    Path(path).write_text(json.dumps(json_safe(data), indent=2, default=str), encoding="utf-8")


def iter_text(value: Any) -> Iterable[str]:
    """Yield text leaves from a TShark JSON value."""
    if isinstance(value, dict):
        for item in value.values():
            yield from iter_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_text(item)
    elif value is not None:
        yield str(value)


def first_value(value: Any, default: Any = None) -> Any:
    """Return the first scalar value from a TShark JSON field."""
    if isinstance(value, list):
        for item in value:
            result = first_value(item)
            if result not in (None, ""):
                return result
    elif isinstance(value, dict):
        for item in value.values():
            result = first_value(item)
            if result not in (None, ""):
                return result
    if value not in (None, ""):
        return value
    return default
