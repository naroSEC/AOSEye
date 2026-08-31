from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Iterable

from .models import ActivityInfo, DeepLinkInfo, ProviderInfo


ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"


def android_attr(node, name: str, default: str = "") -> str:
    value = node.get(ANDROID + name)
    return default if value is None else str(value)


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"true", "1", "0xffffffff"}


def parse_sdk(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def normalize_component_name(package_name: str, name: str) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return package_name + name
    if "." not in name:
        return f"{package_name}.{name}"
    return name


def _has_intent_filter(node) -> bool:
    return any(child.tag == "intent-filter" for child in node)


def _exported_state(node, *, default_if_filter: bool = True) -> tuple[bool, str]:
    raw = node.get(ANDROID + "exported")
    if raw is not None:
        return parse_bool(raw), f"explicit:{str(raw).lower()}"
    inferred = default_if_filter and _has_intent_filter(node)
    return inferred, "implicit:intent-filter" if inferred else "implicit:false"


def _is_launcher(node) -> bool:
    for intent_filter in node.findall("intent-filter"):
        actions = {android_attr(item, "name") for item in intent_filter.findall("action")}
        categories = {android_attr(item, "name") for item in intent_filter.findall("category")}
        if (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        ):
            return True
    return False


def normalize_launch_mode(raw: str) -> str:
    mapping = {"0": "standard", "1": "singleTop", "2": "singleTask", "3": "singleInstance"}
    return mapping.get(raw, raw or "standard")


def activities_from_manifest(root, package_name: str) -> list[ActivityInfo]:
    application = root.find("application")
    if application is None:
        return []
    result: list[ActivityInfo] = []
    for tag in ("activity", "activity-alias"):
        for node in application.findall(tag):
            name = normalize_component_name(package_name, android_attr(node, "name"))
            exported, source = _exported_state(node)
            launch_mode = normalize_launch_mode(android_attr(node, "launchMode"))
            command = f"adb shell am start -n {package_name}/{name}" if exported else ""
            result.append(
                ActivityInfo(
                    name=name,
                    exported=exported,
                    exported_source=source,
                    launch_mode=launch_mode,
                    is_launcher=_is_launcher(node),
                    adb_command=command,
                )
            )
    return result


def providers_from_manifest(root, package_name: str) -> list[ProviderInfo]:
    application = root.find("application")
    if application is None:
        return []
    result: list[ProviderInfo] = []
    for node in application.findall("provider"):
        # Provider defaults depend on targetSdk. Report only explicit true or a decoded true value.
        raw = node.get(ANDROID + "exported")
        exported = parse_bool(raw, default=False)
        if not exported:
            continue
        result.append(
            ProviderInfo(
                name=normalize_component_name(package_name, android_attr(node, "name")),
                authorities=android_attr(node, "authorities"),
                exported=True,
                exported_source=f"explicit:{str(raw).lower()}",
                read_permission=android_attr(node, "readPermission") or android_attr(node, "permission"),
                write_permission=android_attr(node, "writePermission") or android_attr(node, "permission"),
            )
        )
    return result


def requested_permissions(root) -> set[str]:
    tags = ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")
    return {
        android_attr(node, "name")
        for tag in tags
        for node in root.findall(tag)
        if android_attr(node, "name")
    }


def application_bool(root, name: str, default: bool) -> tuple[bool, str]:
    application = root.find("application")
    if application is None:
        return default, "application element missing"
    raw = application.get(ANDROID + name)
    if raw is None:
        return default, f"not declared (Android default: {str(default).lower()})"
    return parse_bool(raw, default), f"declared: {str(raw).lower()}"


def _path_variants(data_nodes: Iterable) -> list[str]:
    paths: list[str] = []
    for node in data_nodes:
        for attr_name in ("path", "pathPrefix", "pathSuffix", "pathPattern", "pathAdvancedPattern"):
            value = android_attr(node, attr_name)
            if value:
                paths.append(value)
    return paths or [""]


def deep_links_from_manifest(root, package_name: str) -> list[DeepLinkInfo]:
    application = root.find("application")
    if application is None:
        return []
    links: dict[tuple[str, str], DeepLinkInfo] = {}
    for tag in ("activity", "activity-alias"):
        for activity in application.findall(tag):
            activity_name = normalize_component_name(package_name, android_attr(activity, "name"))
            for intent_filter in activity.findall("intent-filter"):
                actions = {android_attr(item, "name") for item in intent_filter.findall("action")}
                categories = {android_attr(item, "name") for item in intent_filter.findall("category")}
                if "android.intent.action.VIEW" not in actions:
                    continue
                if "android.intent.category.BROWSABLE" not in categories:
                    continue
                data_nodes = intent_filter.findall("data")
                schemes = sorted({android_attr(item, "scheme") for item in data_nodes if android_attr(item, "scheme")})
                hosts = sorted({android_attr(item, "host") for item in data_nodes if android_attr(item, "host")}) or [""]
                ports = sorted({android_attr(item, "port") for item in data_nodes if android_attr(item, "port")}) or [""]
                paths = _path_variants(data_nodes)
                for scheme, host, port, path in itertools.product(schemes, hosts, ports, paths):
                    authority = host + (f":{port}" if host and port else "")
                    if authority:
                        uri = f"{scheme}://{authority}{path}"
                    else:
                        uri = f"{scheme}:{path}"
                    command = f'adb shell am start -a android.intent.action.VIEW -d "{uri}"'
                    links[(activity_name, uri)] = DeepLinkInfo(activity_name, uri, command)
    return sorted(links.values(), key=lambda item: (item.activity, item.uri))
