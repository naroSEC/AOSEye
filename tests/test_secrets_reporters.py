from __future__ import annotations

import unittest

from aoseye.models import AnalysisReport, AppMetadata, SensitiveString
from aoseye.reporters import render_html, render_text
from aoseye.secrets import scan_sensitive_strings


class SecretsAndReporterTests(unittest.TestCase):
    def test_sensitive_pattern_scanning_deduplicates(self) -> None:
        key = "AKIA" + "A" * 16
        items = scan_sensitive_strings(
            {"endpoint": "https://api.example.com/v1", "aws": key},
            [key, "eu-west-1_AbCdEf123"],
        )
        categories = {item.category for item in items}
        self.assertIn("URL", categories)
        self.assertIn("AWS Access Key ID", categories)
        self.assertIn("AWS Cognito User Pool", categories)
        self.assertEqual(sum(item.value == key for item in items), 1)

    def test_html_escapes_apk_strings(self) -> None:
        metadata = AppMetadata(
            apk_path="C:/tmp/test.apk",
            file_name="<script>.apk",
            sha256="abc",
            size_bytes=1,
            package_name="com.example",
            app_name="Example",
            version_name="1",
            version_code="1",
            min_sdk=21,
            target_sdk=35,
            analyzed_at="now",
        )
        report = AnalysisReport(metadata=metadata)
        report.sensitive_strings.append(SensitiveString("URL", "https://x/?a=<tag>", "DEX"))
        rendered = render_html(report)
        self.assertNotIn("<script>.apk", rendered)
        self.assertIn("&lt;script&gt;.apk", rendered)
        self.assertIn("민감 문자열 후보", rendered)
        self.assertIn("[민감 문자열 후보]", render_text(report))


if __name__ == "__main__":
    unittest.main()
