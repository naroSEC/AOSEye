from __future__ import annotations

import json
import unittest

from aoseye.firebase import check_remote_config, discover_firebase_config


class FakeResponse:
    status = 200

    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode()

    def getcode(self) -> int:
        return self.status

    def read(self, _size: int) -> bytes:
        return self.payload


class FirebaseTests(unittest.TestCase):
    def test_discovers_project_number_from_app_id(self) -> None:
        config = discover_firebase_config(
            {
                "google_api_key": "AIza" + "A" * 35,
                "google_app_id": "1:448220499576:android:abcdef012345",
            }
        )
        self.assertEqual(config.project_number, "448220499576")
        self.assertEqual(config.api_key_source, "google_api_key")

    def test_successful_fetch_is_reported(self) -> None:
        config = discover_firebase_config(
            {
                "google_api_key": "AIza" + "A" * 35,
                "google_app_id": "1:448220499576:android:abcdef012345",
            }
        )
        finding = check_remote_config(
            config,
            network_enabled=True,
            timeout=1,
            opener=lambda *_args, **_kwargs: FakeResponse(
                {"entries": {"start_type": "cold"}, "state": "UPDATE"}
            ),
        )
        self.assertEqual(finding.status, "vulnerable")
        self.assertTrue(any("start_type" in item for item in finding.evidence))

    def test_no_network_is_skipped(self) -> None:
        config = discover_firebase_config(
            {
                "google_api_key": "AIza" + "A" * 35,
                "gcm_defaultSenderId": "448220499576",
            }
        )
        finding = check_remote_config(config, network_enabled=False, timeout=1)
        self.assertEqual(finding.status, "skipped")


if __name__ == "__main__":
    unittest.main()
