from __future__ import annotations

import unittest
from pathlib import Path

from aoseye.cli import _output_path, build_parser


class CliTests(unittest.TestCase):
    def test_default_format_is_html(self) -> None:
        args = build_parser().parse_args(["target.apk"])
        self.assertEqual(args.format, "html")

    def test_output_extension_follows_format(self) -> None:
        output = _output_path("target.apk", "report.txt", "html")
        self.assertEqual(output.suffix, ".html")
        self.assertEqual(output.name, "report.html")

    def test_default_output_name(self) -> None:
        output = _output_path("somewhere/target.apk", None, "txt")
        self.assertEqual(output, Path.cwd() / "target_aoseye_report.txt")


if __name__ == "__main__":
    unittest.main()
