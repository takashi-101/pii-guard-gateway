"""Run the PII Guard Gateway CLI from the repository root without setting PYTHONPATH.

Usage: python pii_guard_cli.py sanitize-csv --input ... --output ... --audit-log ...
       python pii_guard_cli.py verify-log --audit-log ...
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from pii_guard.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
