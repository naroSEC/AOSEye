from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Status = Literal["vulnerable", "safe", "warning", "info", "skipped", "error"]
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    status: Status
    severity: Severity
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass(slots=True)
class ActivityInfo:
    name: str
    exported: bool
    exported_source: str
    launch_mode: str
    is_launcher: bool = False
    adb_command: str = ""


@dataclass(slots=True)
class DeepLinkInfo:
    activity: str
    uri: str
    adb_command: str


@dataclass(slots=True)
class ProviderInfo:
    name: str
    authorities: str
    exported: bool
    exported_source: str
    read_permission: str = ""
    write_permission: str = ""


@dataclass(slots=True)
class SensitiveString:
    category: str
    value: str
    source: str


@dataclass(slots=True)
class AppMetadata:
    apk_path: str
    file_name: str
    sha256: str
    size_bytes: int
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int | None
    target_sdk: int | None
    analyzed_at: str


@dataclass(slots=True)
class AnalysisReport:
    metadata: AppMetadata
    findings: list[Finding] = field(default_factory=list)
    exposed_activities: list[ActivityInfo] = field(default_factory=list)
    deep_links: list[DeepLinkInfo] = field(default_factory=list)
    exported_providers: list[ProviderInfo] = field(default_factory=list)
    all_activities: list[ActivityInfo] = field(default_factory=list)
    sensitive_strings: list[SensitiveString] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def vulnerable_count(self) -> int:
        return sum(item.status == "vulnerable" for item in self.findings)
