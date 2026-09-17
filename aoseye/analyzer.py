from __future__ import annotations

import hashlib
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from lxml import etree

from .androguard_compat import configure_resource_encoding
from .firebase import check_remote_config, discover_firebase_config
from .manifest import (
    activities_from_manifest,
    application_bool,
    deep_links_from_manifest,
    parse_sdk,
    providers_from_manifest,
    requested_permissions,
)
from .models import AnalysisReport, AppMetadata, Finding, Severity
from .secrets import scan_sensitive_strings


HIDE_OVERLAY_PERMISSION = "android.permission.HIDE_OVERLAY_WINDOWS"
KNOWN_SECURITY_LIBRARIES = {
    "libloader.so": "NHN AppGuard",
    "libdxbase.so": "NSHC security solution",
}


class AnalysisError(RuntimeError):
    """Raised when an APK cannot be analyzed."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resource_strings(apk) -> tuple[dict[str, str], list[str]]:
    named: dict[str, str] = {}
    all_values: list[str] = []
    try:
        resources = apk.get_android_resources()
    except Exception:
        return named, all_values
    if resources is None:
        return named, all_values
    for package in resources.get_packages_names():
        try:
            locales = resources.get_locales(package)
        except Exception:
            locales = ["\x00\x00"]
        # Defaults win for well-known Firebase resource names.
        locales = sorted(locales, key=lambda item: item != "\x00\x00")
        for locale in locales:
            try:
                xml_bytes = resources.get_string_resources(package, locale)
                root = etree.fromstring(xml_bytes)
            except Exception:
                continue
            locale_name = "default" if locale == "\x00\x00" else str(locale)
            for node in root.findall("string"):
                name = node.get("name") or "unnamed"
                value = "".join(node.itertext())
                if not value:
                    continue
                all_values.append(value)
                named.setdefault(name, value)
                named.setdefault(f"{package}/{locale_name}/{name}", value)
    return named, all_values


def _dex_strings(dex_files: Iterable) -> list[str]:
    result: list[str] = []
    for dex in dex_files:
        try:
            result.extend(str(value) for value in dex.get_strings() if value)
        except Exception:
            continue
    return result


def _task_hijacking_finding(min_sdk: int | None, activities) -> Finding:
    single_task = [item.name for item in activities if item.launch_mode == "singleTask"]
    evidence = [f"minSdkVersion: {min_sdk if min_sdk is not None else 'unknown'}"]
    evidence.append(
        "singleTask activities: " + (", ".join(single_task) if single_task else "none")
    )
    if min_sdk is None:
        return Finding(
            "TASK_HIJACKING",
            "Task Hijacking",
            "warning",
            "medium",
            "minSdkVersion을 확인할 수 없어 두 조건의 충족 여부를 확정하지 못했습니다.",
            evidence,
            "manifest의 minSdkVersion과 singleTask Activity의 외부 입력 처리 및 taskAffinity를 수동 검토하세요.",
        )
    if min_sdk <= 29 and single_task:
        return Finding(
            "TASK_HIJACKING",
            "Task Hijacking",
            "vulnerable",
            "high",
            "minSdkVersion이 Android 10(API 29) 이하이고 singleTask Activity가 있어 요청된 두 판정 조건을 모두 충족합니다.",
            evidence,
            "singleTask 사용 필요성을 재검토하고, 민감 Activity의 exported/taskAffinity 및 외부 Intent 입력을 제한하세요.",
        )
    return Finding(
        "TASK_HIJACKING",
        "Task Hijacking",
        "safe",
        "info",
        "요청된 Task Hijacking 판정 조건 두 가지가 동시에 충족되지 않았습니다.",
        evidence,
    )


def _overlay_finding(permissions: set[str]) -> Finding:
    protected = HIDE_OVERLAY_PERMISSION in permissions
    return Finding(
        "OVERLAY_FISHING",
        "Overlay Fishing 방어",
        "safe" if protected else "vulnerable",
        "info" if protected else "medium",
        (
            "HIDE_OVERLAY_WINDOWS 권한이 선언되어 overlay 차단 설정이 확인되었습니다."
            if protected
            else "HIDE_OVERLAY_WINDOWS 권한이 선언되지 않아 권한 기반 overlay 차단 설정을 확인할 수 없습니다."
        ),
        [f"{HIDE_OVERLAY_PERMISSION}: {'declared' if protected else 'not declared'}"],
        "Android 12 이상 대상 앱은 android.permission.HIDE_OVERLAY_WINDOWS 선언을 검토하고, 민감 UI에는 obscured touch 방어도 함께 적용하세요."
        if not protected
        else "",
    )


def _bool_setting_finding(
    finding_id: str,
    title: str,
    value: bool,
    source: str,
    severity: Severity,
    recommendation: str,
) -> Finding:
    return Finding(
        finding_id,
        title,
        "vulnerable" if value else "safe",
        severity if value else "info",
        f"유효 설정값이 {'true' if value else 'false'}입니다.",
        [source],
        recommendation if value else "",
    )


def _native_library_finding(apk_files: Iterable[str]) -> Finding:
    hits: list[str] = []
    for path in apk_files:
        base_name = Path(path).name.lower()
        if base_name in KNOWN_SECURITY_LIBRARIES:
            hits.append(f"{path} ({KNOWN_SECURITY_LIBRARIES[base_name]})")
    if hits:
        return Finding(
            "KNOWN_SECURITY_LIBRARIES",
            "알려진 보안 솔루션 라이브러리",
            "info",
            "info",
            f"알려진 보안 솔루션 라이브러리 {len(hits)}개를 찾았습니다.",
            sorted(set(hits)),
        )
    return Finding(
        "KNOWN_SECURITY_LIBRARIES",
        "알려진 보안 솔루션 라이브러리",
        "info",
        "info",
        "libloader.so 또는 libdxbase.so가 발견되지 않았습니다.",
    )


def analyze_apk(
    apk_path: str | os.PathLike[str], *, network_enabled: bool = True, timeout: float = 10.0
) -> AnalysisReport:
    path = Path(apk_path).expanduser().resolve()
    if not path.is_file():
        raise AnalysisError(f"APK 파일을 찾을 수 없습니다: {path}")
    if not zipfile.is_zipfile(path):
        raise AnalysisError(f"유효한 ZIP/APK 형식이 아닙니다: {path}")
    try:
        configure_resource_encoding()
        from androguard.misc import AnalyzeAPK
        from loguru import logger

        logger.disable("androguard")
        apk, dex_files, _analysis = AnalyzeAPK(str(path))
    except ImportError as exc:
        raise AnalysisError("androguard가 설치되지 않았습니다. 'pip install -r requirements.txt'를 실행하세요.") from exc
    except Exception as exc:
        raise AnalysisError(f"Androguard가 APK를 해석하지 못했습니다: {exc}") from exc

    try:
        root = apk.get_android_manifest_xml()
    except Exception as exc:
        raise AnalysisError(f"AndroidManifest.xml을 읽지 못했습니다: {exc}") from exc
    package_name = apk.get_package() or root.get("package", "")
    min_sdk = parse_sdk(apk.get_min_sdk_version())
    target_sdk = parse_sdk(apk.get_target_sdk_version())
    activities = activities_from_manifest(root, package_name)
    exposed = [item for item in activities if item.exported]
    providers = providers_from_manifest(root, package_name)
    deep_links = deep_links_from_manifest(root, package_name)
    permissions = requested_permissions(root)
    debuggable, debuggable_source = application_bool(root, "debuggable", False)
    allow_backup, backup_source = application_bool(root, "allowBackup", True)
    named_resources, _all_resource_values = _resource_strings(apk)
    dex_strings = _dex_strings(dex_files)
    sensitive = scan_sensitive_strings(named_resources, dex_strings)

    metadata = AppMetadata(
        apk_path=str(path),
        file_name=path.name,
        sha256=_sha256(path),
        size_bytes=path.stat().st_size,
        package_name=package_name,
        app_name=apk.get_app_name() or "",
        version_name=apk.get_androidversion_name() or "",
        version_code=str(apk.get_androidversion_code() or ""),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        analyzed_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    )
    report = AnalysisReport(
        metadata=metadata,
        exposed_activities=exposed,
        deep_links=deep_links,
        exported_providers=providers,
        all_activities=activities,
        sensitive_strings=sensitive,
    )
    report.findings.extend(
        [
            _task_hijacking_finding(min_sdk, activities),
            _overlay_finding(permissions),
            _bool_setting_finding(
                "DEBUGGABLE",
                "디버깅 모드",
                debuggable,
                debuggable_source,
                "high",
                "배포 빌드에서는 android:debuggable=false로 설정하고 release 빌드 설정을 확인하세요.",
            ),
            _bool_setting_finding(
                "ALLOW_BACKUP",
                "앱 백업 정책",
                allow_backup,
                backup_source,
                "medium",
                "민감 데이터가 있는 앱은 allowBackup=false 및 Android 12+ dataExtractionRules를 함께 검토하세요.",
            ),
            check_remote_config(
                discover_firebase_config(named_resources),
                network_enabled=network_enabled,
                timeout=timeout,
            ),
            _native_library_finding(apk.get_files()),
            Finding(
                "EXPORTED_ACTIVITIES",
                "외부 노출 Activity",
                "warning" if exposed else "safe",
                "low" if exposed else "info",
                f"외부에서 실행 가능한 Activity/alias가 {len(exposed)}개 발견되었습니다.",
                [f"{item.name} ({item.exported_source})" for item in exposed],
                "각 Activity의 외부 노출 필요성, 권한, Intent 입력 검증을 확인하세요." if exposed else "",
            ),
            Finding(
                "DEEP_LINKS",
                "Deep Link",
                "info",
                "info",
                f"호출 가능한 Deep Link URI 패턴을 {len(deep_links)}개 추출했습니다.",
                [f"{item.activity}: {item.uri}" for item in deep_links],
            ),
            Finding(
                "EXPORTED_PROVIDERS",
                "외부 노출 Content Provider",
                "warning" if providers else "safe",
                "medium" if providers else "info",
                f"android:exported=true인 Content Provider가 {len(providers)}개 발견되었습니다.",
                [f"{item.name} ({item.authorities})" for item in providers],
                "Provider 권한과 URI별 read/write 접근 제어를 확인하세요." if providers else "",
            ),
            Finding(
                "SENSITIVE_STRINGS",
                "민감 문자열 후보",
                "warning" if sensitive else "safe",
                "medium" if sensitive else "info",
                f"리소스/DEX 문자열에서 URL·클라우드 자격정보 등 후보를 {len(sensitive)}개 찾았습니다.",
                [f"{item.category}: {item.value} ({item.source})" for item in sensitive[:100]],
                "후보를 수동 검증하고 실제 비밀값은 APK에 포함하지 말고 서버 측 비밀 저장소로 이동하세요."
                if sensitive
                else "",
            ),
        ]
    )
    if len(sensitive) > 100:
        report.warnings.append(
            f"민감 문자열 finding evidence는 100개로 제한했습니다. 상세 표에는 {len(sensitive)}개가 모두 포함됩니다."
        )
    return report
