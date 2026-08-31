from __future__ import annotations

import unittest

from lxml import etree

from aoseye.manifest import (
    activities_from_manifest,
    application_bool,
    deep_links_from_manifest,
    providers_from_manifest,
    requested_permissions,
)


MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />
  <application android:debuggable="true">
    <activity android:name=".MainActivity" android:exported="true" android:launchMode="singleTask">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="example" />
        <data android:host="open.example.com" android:pathPrefix="/item" />
      </intent-filter>
    </activity>
    <activity android:name="InternalActivity" />
    <activity android:name="ImplicitActivity">
      <intent-filter><action android:name="com.example.OPEN" /></intent-filter>
    </activity>
    <provider android:name=".PublicProvider" android:authorities="com.example.data"
              android:exported="true" android:readPermission="com.example.READ" />
    <provider android:name=".PrivateProvider" android:exported="false" />
  </application>
</manifest>"""


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = etree.fromstring(MANIFEST)

    def test_activity_export_and_launch_mode(self) -> None:
        activities = activities_from_manifest(self.root, "com.example.app")
        by_name = {item.name: item for item in activities}
        main = by_name["com.example.app.MainActivity"]
        self.assertTrue(main.exported)
        self.assertEqual(main.launch_mode, "singleTask")
        self.assertTrue(main.is_launcher)
        self.assertIn("adb shell am start -n", main.adb_command)
        self.assertFalse(by_name["com.example.app.InternalActivity"].exported)
        self.assertEqual(
            by_name["com.example.app.ImplicitActivity"].exported_source,
            "implicit:intent-filter",
        )

    def test_deep_link_combines_data_attributes(self) -> None:
        links = deep_links_from_manifest(self.root, "com.example.app")
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].uri, "example://open.example.com/item")
        self.assertIn('VIEW -d "example://open.example.com/item"', links[0].adb_command)

    def test_provider_only_explicit_true(self) -> None:
        providers = providers_from_manifest(self.root, "com.example.app")
        self.assertEqual([item.name for item in providers], ["com.example.app.PublicProvider"])
        self.assertEqual(providers[0].read_permission, "com.example.READ")

    def test_permissions_and_android_defaults(self) -> None:
        self.assertIn("android.permission.HIDE_OVERLAY_WINDOWS", requested_permissions(self.root))
        self.assertEqual(application_bool(self.root, "debuggable", False), (True, "declared: true"))
        self.assertEqual(
            application_bool(self.root, "allowBackup", True),
            (True, "not declared (Android default: true)"),
        )


if __name__ == "__main__":
    unittest.main()
