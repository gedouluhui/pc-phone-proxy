"""Android product packaging and per-app proxy must be wired through secure storage."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHONE = ROOT / "phone"
sys.path.insert(0, str(PHONE / "src" / "com" / "luhui" / "phoneproxy"))


class AndroidProductTests(unittest.TestCase):
    def test_target_sdk_is_36(self):
        manifest = (PHONE / "AndroidManifest.xml").read_text(encoding="utf-8")
        self.assertIn('android:targetSdkVersion="36"', manifest)
        self.assertIn('android:usesCleartextTraffic="false"', manifest)

    def test_per_app_selection_is_read_from_secure_store(self):
        service = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                   "ProxyVpnService.java").read_text(encoding="utf-8")
        self.assertIn('SecureStore.get(this, "allowed_apps")', service)
        self.assertIn("addAllowedApplication", service)

    def test_apk_is_checked_for_16kb_alignment(self):
        builder = (PHONE / "build_apk.py").read_text(encoding="utf-8")
        self.assertIn('"-P", "16"', builder)
        self.assertIn('"-c", "-P", "16", "4"', builder)

    def test_node_search_filter_and_favorites_are_wired(self):
        activity = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                    "MainActivity.java").read_text(encoding="utf-8")
        self.assertIn("搜索节点 / 地区 / 协议", activity)
        self.assertIn("toggleFavorite", activity)
        self.assertIn("ConfigBuilder.saveFavorites", activity)

    def test_subscription_crud_uses_secure_catalog(self):
        activity = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                    "MainActivity.java").read_text(encoding="utf-8")
        builder = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                   "ConfigBuilder.java").read_text(encoding="utf-8")
        self.assertIn("showSubscriptionManager", activity)
        self.assertIn("SubscriptionCatalog.touch", activity)
        self.assertIn('SecureStore.put(ctx, KEY_SUBSCRIPTIONS', builder)

    def test_secure_catalog_read_failures_do_not_become_empty_writes(self):
        builder = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                   "ConfigBuilder.java").read_text(encoding="utf-8")
        subscriptions = builder.split("public static List<SubscriptionCatalog.Record> loadSubscriptions", 1)[1]
        subscriptions = subscriptions.split("public static boolean saveSubscriptions", 1)[0]
        favorites = builder.split("public static java.util.Set<String> loadFavorites", 1)[1]
        favorites = favorites.split("public static boolean saveFavorites", 1)[0]
        self.assertNotIn("catch", subscriptions)
        self.assertNotIn("catch", favorites)
        activity = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                    "MainActivity.java").read_text(encoding="utf-8")
        manager = activity.split("private void showSubscriptionManager()", 1)[1]
        manager = manager.split("private void updateSubscription", 1)[0]
        self.assertIn("catch", manager)
        self.assertIn("订阅读取失败", manager)

    def test_ci_builds_with_api_36(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("platforms;android-36", workflow)
        self.assertIn("build-tools;36.0.0", workflow)


if __name__ == "__main__":
    unittest.main()
