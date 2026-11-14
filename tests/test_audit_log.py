"""Tamper detection of the hash-chained audit log (AuditLogger.verify_chain / verify-log)."""

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pii_guard import AuditLogger, PIISanitizer
from pii_guard.cli import main as cli_main


class TestAuditLogTampering(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self._tmp.name) / "audit.jsonl"
        self.logger = AuditLogger(self.log_path)
        sanitizer = PIISanitizer()
        for actor, text in [
            ("staff-01", "氏名：架空 太郎 / 電話：000-0000-0000"),
            ("staff-02", "メール：kakuu.taro@example.jp"),
            ("staff-03", "申請額：150万円"),
        ]:
            self.logger.record(actor, "prompt_sanitize", sanitizer.sanitize(text))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _lines(self) -> list:
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def _write(self, lines) -> None:
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _edit_field(self, index: int, key: str, value) -> None:
        lines = self._lines()
        entry = json.loads(lines[index])
        entry[key] = value
        lines[index] = json.dumps(entry, ensure_ascii=False)
        self._write(lines)

    def _verify_cli(self) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return cli_main(["verify-log", "--audit-log", str(self.log_path)])

    # --- untouched log passes -------------------------------------------------

    def test_untouched_log_passes(self) -> None:
        self.assertEqual(self.logger.verify_chain(), (True, 3))
        self.assertEqual(self._verify_cli(), 0)

    def test_each_record_links_to_previous_hash(self) -> None:
        entries = [json.loads(ln) for ln in self._lines()]
        self.assertEqual(entries[0]["prev_hash"], AuditLogger.GENESIS_HASH)
        self.assertEqual(entries[1]["prev_hash"], entries[0]["record_hash"])
        self.assertEqual(entries[2]["prev_hash"], entries[1]["record_hash"])

    # --- tampering that is detected -------------------------------------------

    def test_modified_field_fails(self) -> None:
        for key, value in [
            ("total_masked", 0),
            ("action", "other_action"),
            ("status", "BLOCKED"),
            ("timestamp_utc", "2000-01-01T00:00:00+00:00"),
            ("actor_hash", "0" * 16),
            ("counts_by_type", {"EMAIL": 2}),
        ]:
            with self.subTest(key=key):
                original = self._lines()
                self._edit_field(1, key, value)
                self.assertEqual(self.logger.verify_chain(), (False, 3))
                self.assertEqual(self._verify_cli(), 1)
                self._write(original)
                self.assertEqual(self.logger.verify_chain(), (True, 3))

    def test_added_field_fails(self) -> None:
        self._edit_field(0, "note", "added later")
        self.assertFalse(self.logger.verify_chain()[0])

    def test_deleted_first_line_fails(self) -> None:
        self._write(self._lines()[1:])
        self.assertEqual(self.logger.verify_chain(), (False, 2))

    def test_deleted_middle_line_fails(self) -> None:
        lines = self._lines()
        del lines[1]
        self._write(lines)
        self.assertEqual(self.logger.verify_chain(), (False, 2))
        self.assertEqual(self._verify_cli(), 1)

    def test_reordered_lines_fail(self) -> None:
        for i, j in [(0, 1), (1, 2), (0, 2)]:
            with self.subTest(swap=(i, j)):
                original = self._lines()
                lines = list(original)
                lines[i], lines[j] = lines[j], lines[i]
                self._write(lines)
                self.assertEqual(self.logger.verify_chain(), (False, 3))
                self._write(original)

    def test_duplicated_line_fails(self) -> None:
        lines = self._lines()
        lines.insert(2, lines[1])
        self._write(lines)
        self.assertEqual(self.logger.verify_chain(), (False, 4))

    def test_broken_json_line_fails_without_exception(self) -> None:
        lines = self._lines()
        lines[1] = lines[1][:-5]
        self._write(lines)
        self.assertEqual(self.logger.verify_chain(), (False, 3))
        self.assertEqual(self._verify_cli(), 1)

    def test_non_object_json_line_fails(self) -> None:
        lines = self._lines()
        lines[1] = "[]"
        self._write(lines)
        self.assertEqual(self.logger.verify_chain(), (False, 3))

    # --- limits: tampering that the chain alone does NOT detect ----------------

    def test_limit_deleted_last_line_is_not_detected(self) -> None:
        # Only the record count drops (3 -> 2); keep the count elsewhere to notice.
        self._write(self._lines()[:-1])
        self.assertEqual(self.logger.verify_chain(), (True, 2))

    def test_limit_fully_rehashed_chain_is_not_detected(self) -> None:
        # No secret key is used, so anyone can recompute every hash after an edit.
        prev = AuditLogger.GENESIS_HASH
        rewritten = []
        for i, line in enumerate(self._lines()):
            entry = json.loads(line)
            if i == 0:
                entry["total_masked"] = 0
            body = {k: v for k, v in entry.items() if k != "record_hash"}
            body["prev_hash"] = prev
            record_hash = AuditLogger._compute_record_hash(body)
            rewritten.append(json.dumps({**body, "record_hash": record_hash}, ensure_ascii=False))
            prev = record_hash
        self._write(rewritten)
        self.assertEqual(self.logger.verify_chain(), (True, 3))

    def test_limit_missing_file_is_reported_valid(self) -> None:
        self.log_path.unlink()
        self.assertEqual(self.logger.verify_chain(), (True, 0))
        self.assertEqual(self._verify_cli(), 0)

    # --- contents --------------------------------------------------------------

    def test_log_has_no_raw_values_and_actor_is_unsalted_sha256_prefix(self) -> None:
        raw_log = self.log_path.read_text(encoding="utf-8")
        for secret in ["架空 太郎", "000-0000-0000", "kakuu.taro@example.jp", "150万円", "staff-01"]:
            self.assertNotIn(secret, raw_log)
        first = json.loads(self._lines()[0])
        self.assertEqual(
            first["actor_hash"], hashlib.sha256(b"staff-01").hexdigest()[:16]
        )
        self.assertEqual(
            sorted(first),
            [
                "action",
                "actor_hash",
                "counts_by_type",
                "prev_hash",
                "record_hash",
                "status",
                "timestamp_utc",
                "total_masked",
            ],
        )


if __name__ == "__main__":
    unittest.main()
