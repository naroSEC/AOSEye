from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from .models import SensitiveString


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("URL", re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)),
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("AWS Cognito Identity Pool", re.compile(r"\b[a-z]{2}(?:-gov)?-[a-z]+-\d:[0-9a-fA-F-]{36}\b")),
    ("AWS Cognito User Pool", re.compile(r"\b[a-z]{2}(?:-gov)?-[a-z]+-\d_[A-Za-z0-9]+\b")),
    ("Google/Firebase API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Firebase Database URL", re.compile(r"https://[a-z0-9-]+(?:-default-rtdb)?\.(?:firebaseio\.com|firebasedatabase\.app)(?:/[^\s\"'<>]*)?", re.IGNORECASE)),
    ("Google OAuth Client ID", re.compile(r"\b\d{6,}-[a-z0-9_-]{10,}\.apps\.googleusercontent\.com\b", re.IGNORECASE)),
    ("Private Key Marker", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
)

MAX_VALUE_LENGTH = 500


def flatten_resource_strings(resources: Mapping[str, object]) -> Iterable[tuple[str, str]]:
    for key, value in resources.items():
        if isinstance(value, str):
            yield key, value
        elif isinstance(value, Mapping):
            for inner_name, inner_value in flatten_resource_strings(value):
                yield f"{key}/{inner_name}", inner_value


def scan_sensitive_strings(
    resource_strings: Mapping[str, str], dex_strings: Iterable[str]
) -> list[SensitiveString]:
    candidates: list[tuple[str, str]] = [
        (f"resource:{name}", value) for name, value in resource_strings.items()
    ]
    candidates.extend(("DEX string", value) for value in dex_strings)
    found: dict[tuple[str, str], SensitiveString] = {}
    for source, candidate in candidates:
        if not isinstance(candidate, str) or not candidate:
            continue
        for category, pattern in PATTERNS:
            for match in pattern.finditer(candidate):
                value = match.group(0).rstrip(".,);]")[:MAX_VALUE_LENGTH]
                key = (category, value)
                if key not in found:
                    found[key] = SensitiveString(category, value, source)
    return sorted(found.values(), key=lambda item: (item.category, item.value))
