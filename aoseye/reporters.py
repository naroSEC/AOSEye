from __future__ import annotations

import html
from pathlib import Path

from .models import AnalysisReport


STATUS_LABELS = {
    "vulnerable": "취약",
    "safe": "양호",
    "warning": "검토 필요",
    "info": "정보",
    "skipped": "건너뜀",
    "error": "오류",
}


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _html_list(items: list[str], empty: str = "없음") -> str:
    if not items:
        return f'<p class="muted">{_escape(empty)}</p>'
    return "<ul>" + "".join(f"<li><code>{_escape(item)}</code></li>" for item in items) + "</ul>"


def render_html(report: AnalysisReport) -> str:
    m = report.metadata
    finding_cards = []
    for finding in report.findings:
        recommendation = (
            f'<p><strong>권고:</strong> {_escape(finding.recommendation)}</p>'
            if finding.recommendation
            else ""
        )
        finding_cards.append(
            f"""
            <article class="finding {finding.status}">
              <div class="finding-head">
                <h3>{_escape(finding.title)}</h3>
                <span class="badge">{_escape(STATUS_LABELS[finding.status])}</span>
                <span class="severity">{_escape(finding.severity.upper())}</span>
              </div>
              <p>{_escape(finding.summary)}</p>
              {_html_list(finding.evidence, '근거 없음')}
              {recommendation}
            </article>"""
        )

    exposed_rows = "".join(
        f"<tr><td>{_escape(item.name)}</td><td>{_escape(item.exported_source)}</td>"
        f"<td>{_escape(item.launch_mode)}</td><td><code>{_escape(item.adb_command)}</code></td></tr>"
        for item in report.exposed_activities
    ) or '<tr><td colspan="4" class="muted">없음</td></tr>'
    link_rows = "".join(
        f"<tr><td>{_escape(item.activity)}</td><td><code>{_escape(item.uri)}</code></td>"
        f"<td><code>{_escape(item.adb_command)}</code></td></tr>"
        for item in report.deep_links
    ) or '<tr><td colspan="3" class="muted">없음</td></tr>'
    provider_rows = "".join(
        f"<tr><td>{_escape(item.name)}</td><td>{_escape(item.authorities)}</td>"
        f"<td>{_escape(item.read_permission or '-')}</td><td>{_escape(item.write_permission or '-')}</td></tr>"
        for item in report.exported_providers
    ) or '<tr><td colspan="4" class="muted">없음</td></tr>'
    activity_rows = "".join(
        f"<tr><td>{_escape(item.name)}</td><td>{'true' if item.exported else 'false'}</td>"
        f"<td>{_escape(item.exported_source)}</td><td>{_escape(item.launch_mode)}</td>"
        f"<td>{'yes' if item.is_launcher else ''}</td></tr>"
        for item in report.all_activities
    ) or '<tr><td colspan="5" class="muted">없음</td></tr>'
    sensitive_rows = "".join(
        f"<tr><td>{_escape(item.category)}</td><td><code>{_escape(item.value)}</code></td>"
        f"<td>{_escape(item.source)}</td></tr>"
        for item in report.sensitive_strings
    ) or '<tr><td colspan="3" class="muted">없음</td></tr>'

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AOSEye 분석 보고서 - {_escape(m.file_name)}</title>
<style>
:root{{--bg:#f4f7fb;--card:#fff;--text:#172033;--muted:#667085;--border:#dbe2ea;--red:#b42318;--green:#027a48;--amber:#b54708;--blue:#175cd3}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:32px 20px 64px}}h1{{margin:0 0 8px;font-size:30px}}h2{{margin:36px 0 14px;font-size:22px}}h3{{margin:0;font-size:17px}}
.subtitle,.muted{{color:var(--muted)}}.summary,.finding,.table-wrap{{background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 1px 2px #1018280d}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:0;margin-top:24px;overflow:hidden}}.summary div{{padding:15px;border-right:1px solid var(--border)}}.summary b{{display:block;font-size:12px;color:var(--muted);text-transform:uppercase}}.summary span{{word-break:break-all}}
.finding{{padding:18px;margin-bottom:12px;border-left-width:5px}}.finding.vulnerable{{border-left-color:var(--red)}}.finding.safe{{border-left-color:var(--green)}}.finding.warning,.finding.error{{border-left-color:var(--amber)}}.finding.info,.finding.skipped{{border-left-color:var(--blue)}}
.finding-head{{display:flex;align-items:center;gap:9px;flex-wrap:wrap}}.badge,.severity{{font-size:11px;font-weight:700;border-radius:999px;padding:3px 8px;background:#eef2f6}}.vulnerable .badge{{color:var(--red);background:#fef3f2}}.safe .badge{{color:var(--green);background:#ecfdf3}}.warning .badge,.error .badge{{color:var(--amber);background:#fffaeb}}
ul{{padding-left:21px}}code{{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;vertical-align:top;padding:11px 13px;border-bottom:1px solid var(--border)}}th{{background:#f8fafc;font-size:12px;color:#475467}}tr:last-child td{{border-bottom:0}}.notice{{padding:12px 16px;background:#fffaeb;border:1px solid #fedf89;border-radius:9px}}
</style>
</head>
<body><main>
<h1>AOSEye Android 정적 분석 보고서</h1>
<p class="subtitle">생성 시각: {_escape(m.analyzed_at)}</p>
<section class="summary">
 <div><b>APK</b><span>{_escape(m.file_name)}</span></div><div><b>Package</b><span>{_escape(m.package_name)}</span></div>
 <div><b>Version</b><span>{_escape(m.version_name)} ({_escape(m.version_code)})</span></div><div><b>SDK</b><span>min {_escape(m.min_sdk)} / target {_escape(m.target_sdk)}</span></div>
 <div><b>SHA-256</b><span>{_escape(m.sha256)}</span></div><div><b>취약 판정</b><span>{report.vulnerable_count}</span></div>
</section>
<h2>점검 결과</h2>{''.join(finding_cards)}
{''.join(f'<p class="notice">{_escape(w)}</p>' for w in report.warnings)}
<h2>외부 노출 Activity 및 ADB 명령</h2><div class="table-wrap"><table><thead><tr><th>Activity</th><th>Exported 근거</th><th>Launch mode</th><th>ADB</th></tr></thead><tbody>{exposed_rows}</tbody></table></div>
<h2>Deep Link 및 ADB 명령</h2><div class="table-wrap"><table><thead><tr><th>Activity</th><th>URI</th><th>ADB</th></tr></thead><tbody>{link_rows}</tbody></table></div>
<h2>외부 노출 Content Provider</h2><div class="table-wrap"><table><thead><tr><th>Provider</th><th>Authorities</th><th>Read permission</th><th>Write permission</th></tr></thead><tbody>{provider_rows}</tbody></table></div>
<h2>등록된 전체 Activity</h2><div class="table-wrap"><table><thead><tr><th>Activity</th><th>Exported</th><th>근거</th><th>Launch mode</th><th>Launcher</th></tr></thead><tbody>{activity_rows}</tbody></table></div>
<h2>민감 문자열 후보</h2><div class="table-wrap"><table><thead><tr><th>분류</th><th>값</th><th>출처</th></tr></thead><tbody>{sensitive_rows}</tbody></table></div>
</main></body></html>"""


def render_text(report: AnalysisReport) -> str:
    m = report.metadata
    lines = [
        "AOSEye Android 정적 분석 보고서",
        "=" * 72,
        f"APK: {m.apk_path}",
        f"Package: {m.package_name}",
        f"App/Version: {m.app_name} / {m.version_name} ({m.version_code})",
        f"SDK: min={m.min_sdk}, target={m.target_sdk}",
        f"SHA-256: {m.sha256}",
        f"Analyzed: {m.analyzed_at}",
        f"Vulnerable findings: {report.vulnerable_count}",
        "",
        "[점검 결과]",
    ]
    for index, finding in enumerate(report.findings, 1):
        lines.extend(
            [
                "",
                f"{index}. {finding.title} [{STATUS_LABELS[finding.status]} / {finding.severity.upper()}]",
                f"   {finding.summary}",
            ]
        )
        lines.extend(f"   - {item}" for item in finding.evidence)
        if finding.recommendation:
            lines.append(f"   권고: {finding.recommendation}")

    lines.extend(["", "[외부 노출 Activity 및 ADB 명령]"])
    if report.exposed_activities:
        for item in report.exposed_activities:
            lines.extend((f"- {item.name} ({item.exported_source}, {item.launch_mode})", f"  {item.adb_command}"))
    else:
        lines.append("- 없음")

    lines.extend(["", "[Deep Link 및 ADB 명령]"])
    if report.deep_links:
        for item in report.deep_links:
            lines.extend((f"- {item.activity}: {item.uri}", f"  {item.adb_command}"))
    else:
        lines.append("- 없음")

    lines.extend(["", "[외부 노출 Content Provider]"])
    if report.exported_providers:
        for item in report.exported_providers:
            lines.append(
                f"- {item.name}; authorities={item.authorities}; read={item.read_permission or '-'}; write={item.write_permission or '-'}"
            )
    else:
        lines.append("- 없음")

    lines.extend(["", "[등록된 전체 Activity]"])
    lines.extend(
        f"- {item.name}; exported={str(item.exported).lower()} ({item.exported_source}); launchMode={item.launch_mode}; launcher={str(item.is_launcher).lower()}"
        for item in report.all_activities
    )
    if not report.all_activities:
        lines.append("- 없음")

    lines.extend(["", "[민감 문자열 후보]"])
    lines.extend(
        f"- {item.category}: {item.value} ({item.source})" for item in report.sensitive_strings
    )
    if not report.sensitive_strings:
        lines.append("- 없음")
    if report.warnings:
        lines.extend(["", "[경고]"] + [f"- {item}" for item in report.warnings])
    return "\n".join(lines) + "\n"


def write_report(report: AnalysisReport, output_path: Path, output_format: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_html(report) if output_format == "html" else render_text(report)
    output_path.write_text(content, encoding="utf-8")
