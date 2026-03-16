from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.gui_app import format_bytes, read_log_tail


class GuiHelperTests(unittest.TestCase):
    def test_format_bytes_uses_human_readable_units(self) -> None:
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1536), "1.5 KB")
        self.assertEqual(format_bytes(5 * 1024 * 1024), "5.0 MB")

    def test_read_log_tail_returns_last_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "vpn.log"
            log_path.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")

            self.assertEqual(read_log_tail(log_path, lines=2), "three\nfour")


if __name__ == "__main__":
    unittest.main()
