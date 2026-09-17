from __future__ import annotations

import builtins
import io
import unittest
from functools import partial
from unittest.mock import patch

from androguard.core import api_specific_resources

from aoseye.androguard_compat import configure_resource_encoding


class ResourceEncodingTests(unittest.TestCase):
    def test_permission_loaders_under_cp949(self) -> None:
        original_open = builtins.open
        # Model the implicit encoding on Korean Windows independently of
        # the interpreter's UTF-8 mode. Restore the module after the test.
        with patch.object(
            api_specific_resources, "open",
            partial(io.open, encoding="cp949"), create=True,
        ):
            with self.assertRaises(UnicodeDecodeError):
                api_specific_resources.load_permissions(21)

            configure_resource_encoding()
            permissions = api_specific_resources.load_permissions(21)
            self.assertIn("android.permission.INTERNET", permissions)
            self.assertTrue(api_specific_resources.load_permissions(21, "groups"))
            self.assertTrue(api_specific_resources.load_permission_mappings(24))
            self.assertIs(builtins.open, original_open)

            # Initialization remains safe across multiple APK analyses.
            configure_resource_encoding()
            self.assertEqual(api_specific_resources.load_permissions(21), permissions)


if __name__ == "__main__":
    unittest.main()
