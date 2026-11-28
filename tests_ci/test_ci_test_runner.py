import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import run_ci_tests


class CiTestRunnerTests(unittest.TestCase):
    def test_failure_names_become_annotations(self):
        output = "FAIL: test_example (tests_ci.test_sample.TestCase)\nERROR: test_other\n"
        lines = run_ci_tests.annotations(output)
        self.assertEqual(len(lines), 2)
        self.assertIn("test_example", lines[0])
        self.assertIn("test_other", lines[1])

    def test_percent_is_escaped_for_actions_commands(self):
        lines = run_ci_tests.annotations("FAIL: 100% synthetic\n")
        self.assertIn("100%25", lines[0])


if __name__ == "__main__":
    unittest.main()
