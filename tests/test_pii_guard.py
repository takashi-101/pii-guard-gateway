"""Automated verification suite for PII Guard Gateway (all sample data is fictitious)."""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pii_guard import AuditLogger, PIISanitizer, PolicyConfig


class TestPIIGuard(unittest.TestCase):
    def test_masks_all_japanese_pii_categories(self) -> None:
        raw = (
            "氏名：架空 太郎\n"
            "住所：見本県架空市テスト町1-2-3\n"
            "〒000-0000\n"
            "電話：000-0000-0000\n"
            "メール：kakuu.taro@example.jp\n"
            "番号：0000-0000-0000\n"
            "金額：150万円"
        )
        sanitizer = PIISanitizer()
        res = sanitizer.sanitize(raw)

        for secret in [
            "架空 太郎",
            "見本県架空市テスト町1-2-3",
            "000-0000",
            "000-0000-0000",
            "kakuu.taro@example.jp",
            "0000-0000-0000",
            "150万円",
        ]:
            self.assertNotIn(secret, res.sanitized_text)

        self.assertEqual(res.total_masked, 7)

    def test_deterministic_placeholder_and_in_memory_restore(self) -> None:
        raw = "メール：a@example.com に送信後、a@example.com へ再送。"
        res = PIISanitizer().sanitize(raw)
        self.assertEqual(res.counts_by_type["EMAIL"], 1)
        ai_out = f"確認しました。{res.sanitized_text}"
        restored = res.restore(ai_out)
        self.assertIn("a@example.com", restored)

    def test_restore_only_replaces_exact_placeholders(self) -> None:
        res = PIISanitizer().sanitize("氏名：架空 太郎")
        self.assertEqual(res.restore("[PERSON_1] 様"), "架空 太郎 様")
        # If the AI response alters the placeholder, it is not restored.
        self.assertEqual(res.restore("PERSON_1 様"), "PERSON_1 様")
        self.assertNotIn("架空 太郎", repr(res))

    def test_fail_closed_on_non_string(self) -> None:
        with self.assertRaises(TypeError):
            PIISanitizer().sanitize(None)  # type: ignore[arg-type]

    def test_fail_closed_on_invalid_custom_pattern(self) -> None:
        policy = PolicyConfig(custom_patterns=(("BROKEN", "(unclosed"),))
        with self.assertRaises(re.error):
            PIISanitizer(policy).sanitize("氏名：架空 太郎")

    def test_audit_log_contains_zero_raw_pii_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(log_path)
            sanitizer = PIISanitizer()

            r1 = sanitizer.sanitize("氏名：見本 一郎 / 電話：00-000-0000")
            r2 = sanitizer.sanitize("メール：mihon.hanako@example.jp")
            logger.record("staff-01", "prompt_sanitize", r1)
            logger.record("staff-02", "prompt_sanitize", r2)

            raw_log = log_path.read_text(encoding="utf-8")
            self.assertNotIn("見本 一郎", raw_log)
            self.assertNotIn("00-000-0000", raw_log)
            self.assertNotIn("mihon.hanako@example.jp", raw_log)
            self.assertNotIn("staff-01", raw_log)

            valid, count = logger.verify_chain()
            self.assertTrue(valid)
            self.assertEqual(count, 2)

            # Simulate tampering with record 1
            lines = log_path.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[0])
            tampered["total_masked"] = 999
            lines[0] = json.dumps(tampered, ensure_ascii=False)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            valid_after, _ = logger.verify_chain()
            self.assertFalse(valid_after)

    def test_custom_policy_pattern(self) -> None:
        policy = PolicyConfig(custom_patterns=(("DOC_ID", r"見本第\d+号"),))
        res = PIISanitizer(policy).sanitize("文書番号：見本第0001号を受領")
        self.assertNotIn("見本第0001号", res.sanitized_text)
        self.assertEqual(res.counts_by_type["DOC_ID"], 1)

    def test_single_line_slash_separated_record_preserves_structure(self) -> None:
        raw = "氏名：架空 太郎 / 連絡先：000-0000-0000 / メール：kakuu.taro@example.jp / 申請額：150万円の件で確認したい。"
        res = PIISanitizer().sanitize(raw)
        self.assertIn("[PERSON_1]", res.sanitized_text)
        self.assertIn("[PHONE_1]", res.sanitized_text)
        self.assertIn("[EMAIL_1]", res.sanitized_text)
        self.assertIn("[AMOUNT_1]", res.sanitized_text)
        self.assertIn("の件で確認したい。", res.sanitized_text)


if __name__ == "__main__":
    unittest.main()
