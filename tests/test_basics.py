import os
import tempfile
import unittest
from pathlib import Path

from fim.monitor import build_baseline, diff_states


class TestFIM(unittest.TestCase):
    def test_baseline_and_diff(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            f1 = root / "a.txt"
            f1.write_text("hello")

            cfg_paths = [root]
            baseline = build_baseline(cfg_paths, excludes=[], algorithm="sha256",
                                      follow_symlinks=False, ignore_hidden=True)
            self.assertIn(str(f1), baseline)

            # Modify file
            f1.write_text("hello world")
            current = build_baseline(cfg_paths, excludes=[], algorithm="sha256",
                                     follow_symlinks=False, ignore_hidden=True)
            result = diff_states(baseline, current)
            self.assertIn(str(f1), result["modified"])


if __name__ == "__main__":
    unittest.main()
