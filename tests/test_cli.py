"""CLI behavior on CSV input, and the README sample output staying in sync."""

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pii_guard import AuditLogger
from pii_guard.cli import main as cli_main

SAMPLE_CSV = ROOT / "examples" / "sample_inquiries.csv"

EXPECTED_SAMPLE_ROWS = [
    ["ticket_id", "category", "body"],
    [
        "INQ-001",
        "補助金照会",
        "氏名：[PERSON_1] / 連絡先：[PHONE_1] / メール：[EMAIL_1] / 申請額：[AMOUNT_1]の件で確認したい。",
    ],
    [
        "INQ-002",
        "施設利用",
        "住所：[ADDRESS_1]（[POSTAL_1]）の担当：[PERSON_1]様宛てに資料を送付希望。",
    ],
    ["INQ-003", "マイナンバー関連", "個人番号：[ID_NUM_1] の紐付け状況について照会。"],
    [
        "INQ-004",
        "検出できない例",
        "架空 次郎さんから、kakuu.jiro@example.jpまで返信がほしいと連絡あり。",
    ],
]


def _run(argv) -> tuple:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_main(argv)
    return code, buf.getvalue()


def _read_rows(path: Path) -> list:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _sanitize(self, input_path: Path) -> tuple:
        out = self.tmp / "out" / "sanitized.csv"
        log = self.tmp / "out" / "audit.jsonl"
        code, stdout = _run(
            ["sanitize-csv", "--input", str(input_path), "--output", str(out), "--audit-log", str(log)]
        )
        return code, stdout, out, log

    def test_sample_csv_output(self) -> None:
        code, stdout, out, log = self._sanitize(SAMPLE_CSV)
        self.assertEqual(code, 0)
        summary = json.loads(stdout)
        self.assertEqual(summary["processed_rows"], 4)
        self.assertEqual(summary["total_masked_entities"], 8)
        self.assertEqual(_read_rows(out), EXPECTED_SAMPLE_ROWS)
        # One audit record per cell that had at least one detection (INQ-001..003 body).
        self.assertEqual(AuditLogger(log).verify_chain(), (True, 3))

    def test_readme_shows_the_actual_sample_output(self) -> None:
        _, _, out, _ = self._sanitize(SAMPLE_CSV)
        actual = "\n".join(out.read_text(encoding="utf-8").splitlines())
        readme = "\n".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines())
        self.assertIn(actual, readme)
        sample = "\n".join(SAMPLE_CSV.read_text(encoding="utf-8").splitlines())
        self.assertIn(sample, readme)

    def test_column_header_is_not_treated_as_label(self) -> None:
        src = self.tmp / "in.csv"
        src.write_text("id,氏名,住所\n1,架空 太郎,見本県架空市テスト町1-2-3\n", encoding="utf-8")
        code, stdout, out, log = self._sanitize(src)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["total_masked_entities"], 0)
        self.assertEqual(_read_rows(out)[1], ["1", "架空 太郎", "見本県架空市テスト町1-2-3"])
        self.assertFalse(log.exists())

    def test_placeholder_numbers_restart_in_each_cell(self) -> None:
        src = self.tmp / "in.csv"
        src.write_text("id,body\n1,氏名：架空 太郎\n2,氏名：見本 花子\n", encoding="utf-8")
        _, _, out, _ = self._sanitize(src)
        rows = _read_rows(out)
        self.assertEqual(rows[1][1], "氏名：[PERSON_1]")
        self.assertEqual(rows[2][1], "氏名：[PERSON_1]")

    def test_row_with_extra_columns_stops_processing(self) -> None:
        src = self.tmp / "in.csv"
        src.write_text(
            "id,body\n1,氏名：架空 太郎\n2,氏名：見本 花子,余分な列\n3,氏名：架空 次郎\n",
            encoding="utf-8",
        )
        with self.assertRaises(TypeError):
            self._sanitize(src)
        out_text = (self.tmp / "out" / "sanitized.csv").read_text(encoding="utf-8")
        self.assertIn("[PERSON_1]", out_text)  # row 1 was already written (sanitized)
        self.assertNotIn("見本 花子", out_text)
        self.assertNotIn("架空 次郎", out_text)


if __name__ == "__main__":
    unittest.main()
