"""Pins what each mask target detects and what it does NOT detect (current behavior).

The "not detected" and "partially detected" cases document real limits of the
regex-based detectors. They are listed in README (検出できない範囲). If a detector
is improved, update the expectation here and the README together.
All sample values are fictitious.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pii_guard import PIISanitizer

SANITIZER = PIISanitizer()


class _Base(unittest.TestCase):
    def assert_outputs(self, cases) -> None:
        """cases: iterable of (raw_text, expected_sanitized_text)."""
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(SANITIZER.sanitize(raw).sanitized_text, expected)

    def assert_unchanged(self, raws) -> None:
        for raw in raws:
            with self.subTest(raw=raw):
                res = SANITIZER.sanitize(raw)
                self.assertEqual(res.sanitized_text, raw)
                self.assertEqual(res.total_masked, 0)


class TestPersonName(_Base):
    """氏名: only text right after a label (氏名/名前/申請者/担当者/対象者/担当) and a colon."""

    def test_detected_after_label_and_colon(self) -> None:
        self.assert_outputs(
            [
                ("氏名：架空 太郎", "氏名：[PERSON_1]"),
                ("氏名:架空太郎", "氏名:[PERSON_1]"),
                ("お名前：架空 太郎", "お名前：[PERSON_1]"),
                ("申請者：架空 太郎様", "申請者：[PERSON_1]様"),
                ("担当：見本 花子さん", "担当：[PERSON_1]さん"),
                ("担当者：見本 花子の件", "担当者：[PERSON_1]の件"),
                ("対象者：架空 太郎、年齢：40", "対象者：[PERSON_1]、年齢：40"),
            ]
        )

    def test_not_detected_without_label_or_colon(self) -> None:
        self.assert_unchanged(
            [
                "架空 太郎さんから電話がありました",  # no label
                "氏名 架空 太郎",  # label without colon
                "氏名　架空太郎",  # full-width space instead of colon
                "氏名＝架空太郎",  # other separator
                "代表者：架空 太郎",  # label not in the list
                "Name: Taro Kakuu",  # English label
            ]
        )

    def test_reading_in_brackets_is_not_masked(self) -> None:
        self.assert_outputs(
            [("名前：架空 太郎（カクウ タロウ）", "名前：[PERSON_1]（カクウ タロウ）")]
        )

    def test_over_masking_until_delimiter(self) -> None:
        # Everything up to the next delimiter is treated as the name.
        self.assert_outputs(
            [
                ("氏名：架空 太郎 です", "氏名：[PERSON_1]"),
                ("氏名：架空太郎 電話：000-0000-0000", "氏名：[PERSON_1][PHONE_1]"),
            ]
        )
        res = SANITIZER.sanitize("氏名：架空 太郎 です")
        self.assertEqual(res.restore("[PERSON_1]"), "架空 太郎 です")


class TestPhone(_Base):
    """電話: starts with 0; hyphenated (0x-x-x) or 10-11 consecutive digits."""

    def test_detected(self) -> None:
        self.assert_outputs(
            [
                ("電話：000-0000-0000", "電話：[PHONE_1]"),
                ("電話：00-0000-0000", "電話：[PHONE_1]"),
                ("電話：000-000-0000", "電話：[PHONE_1]"),
                ("電話：00000000000", "電話：[PHONE_1]"),  # 11 digits
                ("電話：0000000000", "電話：[PHONE_1]"),  # 10 digits
                ("電話番号は000-0000-0000です", "電話番号は[PHONE_1]です"),
            ]
        )

    def test_not_detected(self) -> None:
        self.assert_unchanged(
            [
                "電話：+81-90-0000-0000",  # international format
                "電話：(000)0000-0000",  # parentheses
                "電話：000 0000 0000",  # spaces
                "電話：000－0000－0000",  # full-width hyphen
                "電話：000000000",  # 9 digits
            ]
        )

    def test_full_width_digits_are_not_detected_as_phone(self) -> None:
        # The first 7 digits match the postal-code rule; the last 4 digits remain.
        self.assert_outputs(
            [("電話：０００-００００-００００", "電話：[POSTAL_1]-００００")]
        )

    def test_false_positive_on_zero_leading_date(self) -> None:
        self.assert_outputs([("日付：01-02-2026", "日付：[PHONE_1]")])


class TestEmail(_Base):
    """メール: ASCII local part, '@', ASCII domain; needs a word boundary on both ends."""

    def test_detected(self) -> None:
        self.assert_outputs(
            [
                ("メール：kakuu.taro@example.jp", "メール：[EMAIL_1]"),
                ("kakuu.taro+tag@sub.example.jp まで", "[EMAIL_1] まで"),
                ("KAKUU@EXAMPLE.JP", "[EMAIL_1]"),
            ]
        )

    def test_not_detected_when_touching_japanese_text(self) -> None:
        # Japanese characters count as word characters, so \b does not match.
        self.assert_unchanged(
            [
                "kakuu.taro@example.jpまでご連絡ください",
                "メールkakuu@example.jp",
            ]
        )

    def test_not_detected_other_notations(self) -> None:
        self.assert_unchanged(
            [
                "連絡先 kakuu＠example.jp",  # full-width @
                "kakuu [at] example.jp",  # obfuscated
                "架空@example.jp",  # non-ASCII local part
                "kakuu@例え.jp",  # non-ASCII domain
            ]
        )


class TestMyNumber(_Base):
    """個人番号: 4-4-4 digits or 12 consecutive digits. Check digit is not verified."""

    def test_detected(self) -> None:
        self.assert_outputs(
            [
                ("個人番号：0000-0000-0000", "個人番号：[ID_NUM_1]"),
                ("個人番号：000000000000", "個人番号：[ID_NUM_1]"),
                ("個人番号：００００００００００００", "個人番号：[ID_NUM_1]"),
            ]
        )

    def test_not_detected(self) -> None:
        self.assert_unchanged(
            [
                "個人番号：0000 0000 0000",  # spaces
                "個人番号：0000－0000－0000",  # full-width hyphen
                "個人番号：0000-00000000",  # other grouping
                "個人番号：11111111111",  # 11 digits
                "番号：0000000000000",  # 13 digits
            ]
        )

    def test_any_12_digit_number_is_masked(self) -> None:
        self.assert_outputs([("注文番号：123456789012", "注文番号：[ID_NUM_1]")])


class TestAddress(_Base):
    """住所: only text after 住所/所在地 + colon. 郵便番号: 3-4 digits (with optional 〒)."""

    def test_detected_after_label_and_colon(self) -> None:
        self.assert_outputs(
            [
                ("住所：見本県架空市テスト町1-2-3", "住所：[ADDRESS_1]"),
                ("所在地：見本県架空市テスト町1-2-3", "所在地：[ADDRESS_1]"),
                ("現住所：見本県架空市テスト町1-2-3", "現住所：[ADDRESS_1]"),
                ("住所：見本県架空市テスト町1-2-3宛", "住所：[ADDRESS_1]宛"),
                (
                    "住所：見本県架空市テスト町1-2-3 架空ビル101号室",
                    "住所：[ADDRESS_1]",
                ),
                (
                    "住所：見本県架空市テスト町1-2-3、電話：000-0000-0000",
                    "住所：[ADDRESS_1]、電話：[PHONE_1]",
                ),
            ]
        )

    def test_not_detected_without_label_or_colon(self) -> None:
        self.assert_unchanged(
            [
                "見本県架空市テスト町1-2-3に住んでいます",  # no label
                "住所 見本県架空市テスト町1-2-3",  # label without colon
                "送付先：見本県架空市テスト町1-2-3",  # label not in the list
            ]
        )

    def test_postal_code_detected(self) -> None:
        self.assert_outputs(
            [
                ("〒000-0000", "[POSTAL_1]"),
                ("〒 000-0000", "[POSTAL_1]"),
                ("（〒000-0000）", "（[POSTAL_1]）"),
                ("郵便番号：000-0000", "郵便番号：[POSTAL_1]"),
                ("〒０００-００００", "[POSTAL_1]"),
            ]
        )

    def test_postal_code_not_detected(self) -> None:
        self.assert_unchanged(
            [
                "郵便番号000-0000",  # touching Japanese text (no word boundary)
                "〒000-0000見本県",  # touching Japanese text (no word boundary)
                "〒0000000",  # no hyphen
                "〒０００－００００",  # full-width hyphen
            ]
        )


class TestAmount(_Base):
    """金額: digits (comma grouping allowed) + 円/万円/億円."""

    def test_detected(self) -> None:
        self.assert_outputs(
            [
                ("申請額：150万円", "申請額：[AMOUNT_1]"),
                ("金額：1,500,000円", "金額：[AMOUNT_1]"),
                ("金額：1500000円", "金額：[AMOUNT_1]"),
                ("金額：3億円", "金額：[AMOUNT_1]"),
                ("金額：500 円", "金額：[AMOUNT_1]"),
                ("金額：150 万円", "金額：[AMOUNT_1]"),
                ("金額：１５０万円", "金額：[AMOUNT_1]"),
            ]
        )

    def test_not_detected(self) -> None:
        self.assert_unchanged(
            [
                "金額：¥1,500,000",  # yen sign
                "金額：1,500,000 JPY",  # currency code
                "金額：百五十万円",  # kanji numerals
                "金額：1万5千円",  # mixed units
                "金額：5千円",  # 千円
                "金額：150万",  # no 円
                "金額：150万ドル",  # other currency
            ]
        )

    def test_decimal_amount_is_partially_masked(self) -> None:
        self.assert_outputs([("金額：1.5億円", "金額：1.[AMOUNT_1]")])


if __name__ == "__main__":
    unittest.main()
