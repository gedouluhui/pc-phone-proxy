"""Harvest must never fall back to an unbounded or unpinned downloader."""
import hashlib
import os
import sys
import unittest
from pathlib import Path

from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import harvest


class HarvestFetchTests(unittest.TestCase):
    def test_success_uses_hardened_fetcher_and_records_digest(self):
        body = b"1.2.3.4:8080\n"
        legacy = mock.Mock()
        with mock.patch.object(harvest, "BOOTSTRAP", "http://127.0.0.1:2086"), \
             mock.patch.object(harvest.source_fetch, "fetch", return_value=body) as fetch, \
             mock.patch.dict(sys.modules, {"requests": legacy}):
            result = harvest.fetch("sample", "https://example.com/list", timeout=12)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], body)
        self.assertEqual(result["sha256"], hashlib.sha256(body).hexdigest())
        fetch.assert_called_once_with("https://example.com/list", timeout=12,
                                      proxy="http://127.0.0.1:2086")
        legacy.assert_not_called()

    def test_query_token_is_not_preserved_in_reporting_url(self):
        with mock.patch.object(harvest, "BOOTSTRAP", ""), \
             mock.patch.object(harvest.source_fetch, "fetch", return_value=b"ok"):
            result = harvest.fetch("sample", "https://example.com/list?token=synthetic-secret")
        self.assertNotIn("synthetic-secret", result["url"])
        self.assertNotIn("token", result["url"])
        self.assertEqual(result["fetch_url"],
                         "https://example.com/list?token=synthetic-secret")

    def test_source_summary_keeps_hash_but_not_body_or_fetch_url(self):
        row = harvest.summarize({"slug": "sample", "url": "https://example.com/list",
                                 "fetch_url": "https://example.com/list?token=x",
                                 "status": 200, "bytes": 2, "secs": 0.1, "ok": True,
                                 "sha256": "a" * 64, "body": b"ok"})
        self.assertEqual(row["sha256"], "a" * 64)
        self.assertNotIn("body", row)
        self.assertNotIn("fetch_url", row)

    def test_rejected_source_has_no_unpinned_retry(self):
        legacy = mock.Mock()
        with mock.patch.object(harvest, "BOOTSTRAP", ""), \
             mock.patch.object(harvest.source_fetch, "fetch",
                               side_effect=harvest.source_fetch.Rejected("private address")), \
             mock.patch.dict(sys.modules, {"requests": legacy}):
            result = harvest.fetch("sample", "http://127.0.0.1/list")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertEqual(result["body"], b"")
        self.assertIn("private address", result["err"])
        legacy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
