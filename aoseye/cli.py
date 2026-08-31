from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import AnalysisError, analyze_apk
from .reporters import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aoseye",
        description="Androguard 기반 Android APK 정적 보안 분석기",
    )
    parser.add_argument("apk", help="분석할 APK 파일 경로")
    parser.add_argument(
        "-f",
        "--format",
        choices=("html", "txt"),
        default="html",
        help="리포트 형식 (기본: html)",
    )
    parser.add_argument("-o", "--output", help="리포트 저장 경로")
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Firebase Remote Config 원격 확인을 수행하지 않음",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Firebase 요청 제한 시간(초, 기본: 10)",
    )
    parser.add_argument(
        "--fail-on-vulnerable",
        action="store_true",
        help="취약 판정이 하나 이상이면 종료 코드 1 반환(CI용)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _output_path(apk: str, output: str | None, output_format: str) -> Path:
    if output:
        path = Path(output).expanduser()
        if path.suffix.lower() != f".{output_format}":
            path = path.with_suffix(f".{output_format}")
        return path.resolve()
    apk_path = Path(apk)
    return Path.cwd() / f"{apk_path.stem}_aoseye_report.{output_format}"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout은 0보다 커야 합니다.")
    destination = _output_path(args.apk, args.output, args.format)
    try:
        report = analyze_apk(
            args.apk,
            network_enabled=not args.no_network,
            timeout=args.timeout,
        )
        write_report(report, destination, args.format)
    except AnalysisError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[ERROR] 리포트를 저장하지 못했습니다: {exc}", file=sys.stderr)
        return 2
    print(f"[OK] 분석 완료: {report.metadata.package_name or report.metadata.file_name}")
    print(f"[OK] 취약 판정: {report.vulnerable_count}개")
    print(f"[OK] 리포트: {destination}")
    return 1 if args.fail_on_vulnerable and report.vulnerable_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
