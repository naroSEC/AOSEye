from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .models import Finding


@dataclass(slots=True)
class FirebaseConfig:
    api_key: str = ""
    app_id: str = ""
    project_number: str = ""
    api_key_source: str = ""
    app_id_source: str = ""
    project_number_source: str = ""


def _first_named(resources: dict[str, str], names: tuple[str, ...]) -> tuple[str, str]:
    lowered = {name.lower(): (name, value) for name, value in resources.items()}
    for wanted in names:
        if wanted.lower() in lowered:
            return lowered[wanted.lower()]
    return "", ""


def discover_firebase_config(resources: dict[str, str]) -> FirebaseConfig:
    key_name, key = _first_named(resources, ("google_api_key", "current_key", "firebase_api_key"))
    app_name, app_id = _first_named(resources, ("google_app_id", "mobilesdk_app_id", "firebase_app_id"))
    project_name, project_number = _first_named(
        resources, ("gcm_defaultSenderId", "gcm_default_sender_id", "project_number")
    )
    if not key:
        for name, value in resources.items():
            match = re.search(r"\bAIza[0-9A-Za-z_-]{35}\b", value)
            if match:
                key_name, key = name, match.group(0)
                break
    if not app_id:
        for name, value in resources.items():
            if re.fullmatch(r"1:\d+:android:[0-9a-fA-F]+", value):
                app_name, app_id = name, value
                break
    if not project_number and app_id:
        parts = app_id.split(":")
        if len(parts) >= 2 and parts[1].isdigit():
            project_number = parts[1]
            project_name = f"derived from {app_name}"
    return FirebaseConfig(
        api_key=key,
        app_id=app_id,
        project_number=project_number,
        api_key_source=key_name,
        app_id_source=app_name,
        project_number_source=project_name,
    )


def _masked_key(key: str) -> str:
    if len(key) < 12:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


def check_remote_config(
    config: FirebaseConfig,
    *,
    network_enabled: bool,
    timeout: float,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> Finding:
    base_evidence = []
    if config.api_key:
        base_evidence.append(
            f"Firebase API key: {_masked_key(config.api_key)} (resource: {config.api_key_source})"
        )
    if config.app_id:
        base_evidence.append(f"Firebase app ID: {config.app_id} (resource: {config.app_id_source})")
    if config.project_number:
        base_evidence.append(
            f"Project number: {config.project_number} (source: {config.project_number_source})"
        )

    if not config.api_key and not config.app_id and not config.project_number:
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "safe",
            "info",
            "Firebase Remote Config 관련 리소스가 발견되지 않았습니다.",
        )
    if not config.api_key or not config.project_number:
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "warning",
            "low",
            "Firebase 설정 일부를 찾았지만 API key와 project number를 모두 확보하지 못해 원격 확인을 수행할 수 없습니다.",
            base_evidence,
            "google-services.json에서 생성되는 google_api_key, google_app_id, gcm_defaultSenderId 리소스를 확인하세요.",
        )
    if not network_enabled:
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "skipped",
            "info",
            "Firebase 설정을 찾았지만 --no-network 옵션으로 원격 확인을 건너뛰었습니다.",
            base_evidence,
        )

    endpoint = (
        "https://firebaseremoteconfig.googleapis.com/v1/projects/"
        f"{urllib.parse.quote(config.project_number, safe='')}/namespaces/firebase:fetch"
        f"?key={urllib.parse.quote(config.api_key, safe='')}"
    )
    payload = {
        "appId": config.app_id,
        "appInstanceId": "aoseye-static-analysis",
        "appInstanceIdToken": "aoseye-static-analysis",
        "languageCode": "ko-KR",
        "countryCode": "KR",
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        response = opener(request, timeout=timeout)
        status = int(getattr(response, "status", response.getcode()))
        body = response.read(1_048_577)
        if len(body) > 1_048_576:
            body = body[:1_048_576]
            base_evidence.append("Response truncated at 1 MiB")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read(1_048_576)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "error",
            "info",
            f"Firebase Remote Config 요청에 실패했습니다: {exc}",
            base_evidence,
            "네트워크 연결과 프록시/방화벽 설정을 확인한 뒤 다시 실행하세요.",
        )

    decoded = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(decoded) if decoded else {}
        rendered = json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True)
    except json.JSONDecodeError:
        parsed = None
        rendered = decoded
    base_evidence.extend((f"HTTP status: {status}", f"Response: {rendered or '<empty>'}"))
    if status == 200:
        entries = parsed.get("entries") if isinstance(parsed, dict) else None
        detail = f" ({len(entries)} entries)" if isinstance(entries, dict) else ""
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "vulnerable",
            "medium",
            f"클라이언트 자격정보만으로 Remote Config 응답을 받았습니다{detail}. 구성 값에 민감정보가 없는지 검토해야 합니다.",
            base_evidence,
            "Remote Config에 비밀정보를 저장하지 말고, 민감 데이터는 인증·인가가 적용된 서버에서 제공하세요.",
        )
    if status in {401, 403}:
        return Finding(
            "FIREBASE_REMOTE_CONFIG",
            "Firebase Remote Config 노출",
            "safe",
            "info",
            "Remote Config endpoint가 요청을 거부했습니다. 이 검사 방식으로 공개 구성 값을 가져올 수 없습니다.",
            base_evidence,
        )
    return Finding(
        "FIREBASE_REMOTE_CONFIG",
        "Firebase Remote Config 노출",
        "warning",
        "low",
        f"Remote Config endpoint가 HTTP {status}를 반환하여 노출 여부를 확정하지 못했습니다.",
        base_evidence,
        "응답 내용과 Firebase 프로젝트 설정을 수동으로 확인하세요.",
    )
