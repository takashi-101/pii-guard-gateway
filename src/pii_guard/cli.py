"""CLI entrypoint for PII Guard Gateway."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .sanitizer import AuditLogger, PIISanitizer


def cmd_sanitize_csv(args: argparse.Namespace) -> int:
    sanitizer = PIISanitizer()
    logger = AuditLogger(args.audit_log)
    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    processed = 0
    total_masked = 0
    with in_path.open("r", encoding="utf-8", newline="") as fin, out_path.open(
        "w", encoding="utf-8", newline=""
    ) as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            new_row = {}
            for k, v in row.items():
                res = sanitizer.sanitize(v or "")
                new_row[k] = res.sanitized_text
                total_masked += res.total_masked
                if res.total_masked > 0:
                    logger.record(args.actor, f"csv_sanitize:{k}", res)
            writer.writerow(new_row)
            processed += 1

    print(
        json.dumps(
            {
                "processed_rows": processed,
                "total_masked_entities": total_masked,
                "output": out_path.as_posix(),
                "audit_log": Path(args.audit_log).as_posix(),
            },
            ensure_ascii=False,
        )
    )
    return 0


def cmd_verify_log(args: argparse.Namespace) -> int:
    logger = AuditLogger(args.audit_log)
    valid, count = logger.verify_chain()
    print(json.dumps({"valid": valid, "records": count}, ensure_ascii=False))
    return 0 if valid else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PII Guard Gateway CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_csv = sub.add_parser("sanitize-csv", help="Sanitize a CSV file and write audit log")
    p_csv.add_argument("--input", required=True)
    p_csv.add_argument("--output", required=True)
    p_csv.add_argument("--audit-log", default="logs/audit.jsonl")
    p_csv.add_argument("--actor", default="operator-01")
    p_csv.set_defaults(func=cmd_sanitize_csv)

    p_ver = sub.add_parser("verify-log", help="Verify hash-chain integrity of audit log")
    p_ver.add_argument("--audit-log", required=True)
    p_ver.set_defaults(func=cmd_verify_log)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
