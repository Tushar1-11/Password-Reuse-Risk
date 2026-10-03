import tempfile
import unittest
from pathlib import Path

from analyzer import PasswordReuseAnalyzer


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.analyzer = PasswordReuseAnalyzer(str(root / "test.sqlite3"), str(root / "key"))
        self.analyzer.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def test_matching_password_creates_high_risk_group(self):
        self.analyzer.add_entry("Email", "correct horse battery staple", "critical")
        result = self.analyzer.add_entry("Bank", "correct horse battery staple", "important")
        dashboard = self.analyzer.dashboard()
        self.assertTrue(result["reused"])
        self.assertEqual(result["reused_on"], ["Email"])
        self.assertEqual(dashboard["summary"]["reused_accounts"], 2)
        self.assertEqual(dashboard["reuse_groups"][0]["level"], "High")

    def test_unique_password_is_low_risk(self):
        self.analyzer.add_entry("Email", "unique", "standard")
        dashboard = self.analyzer.dashboard()
        self.assertEqual(dashboard["entries"][0]["risk_level"], "Low")
        self.assertEqual(dashboard["entries"][0]["risk_score"], 0)

    def test_duplicate_platform_is_rejected(self):
        self.analyzer.add_entry("Email", "one", "standard")
        with self.assertRaisesRegex(ValueError, "already has a record"):
            self.analyzer.add_entry("email", "two", "standard")
