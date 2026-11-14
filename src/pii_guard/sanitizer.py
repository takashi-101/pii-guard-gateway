"""Core PII sanitization, in-memory restoration, and hash-chained audit logging.

Design principles:
1. Fail-closed: Any unexpected error during policy evaluation blocks outbound text.
2. Zero PII in logs: Audit logs record only counts, categories, and SHA-256 chain hashes.
3. Zero external dependencies: Runs in air-gapped / closed environments with Python stdlib.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Pattern, Tuple


@dataclass(frozen=True)
class PolicyConfig:
    """Controls which PII categories are masked before AI/external processing."""

    mask_mynumber: bool = True
    mask_email: bool = True
    mask_phone: bool = True
    mask_postal_code: bool = True
    mask_labeled_person: bool = True
    mask_labeled_address: bool = True
    mask_currency: bool = True
    custom_patterns: Tuple[Tuple[str, str], ...] = ()


@dataclass
class SanitizationResult:
    """Holds sanitized text and an in-memory-only restoration map."""

    sanitized_text: str
    counts_by_type: Dict[str, int]
    _token_map: Dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def total_masked(self) -> int:
        return sum(self.counts_by_type.values())

    def restore(self, ai_response_text: str) -> str:
        """Restores placeholders back to original values strictly inside local memory."""
        restored = ai_response_text
        for placeholder, original in self._token_map.items():
            restored = restored.replace(placeholder, original)
        return restored


class PIISanitizer:
    """Deterministic regex-based PII sanitizer with in-memory token vault."""

    _EMAIL_RE: Pattern[str] = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    _PHONE_RE: Pattern[str] = re.compile(
        r"(?<!\d)(?:0\d{1,4}-\d{1,4}-\d{3,4}|0[789]0\d{8}|0\d{9,10})(?!\d)"
    )
    _POSTAL_RE: Pattern[str] = re.compile(r"〒?\s?\b\d{3}-\d{4}\b")
    _MYNUMBER_RE: Pattern[str] = re.compile(
        r"(?<!\d)(?:\d{4}-\d{4}-\d{4}|\d{12})(?!\d)"
    )
    _LABELED_PERSON_RE: Pattern[str] = re.compile(
        r"((?:氏名|名前|申請者|担当者|対象者|担当)\s*[:：]\s*)([^\n、。,\/／(（\[]+?)(?=\s*(?:[\n、。,\/／(（\[]|様|さん|の件|$))"
    )
    _LABELED_ADDRESS_RE: Pattern[str] = re.compile(
        r"((?:住所|所在地)\s*[:：]\s*)([^\n、。,\/／(（\[]+?)(?=\s*(?:[\n、。,\/／(（\[]|の担当|宛|$))"
    )
    _CURRENCY_RE: Pattern[str] = re.compile(
        r"(?<!\d)(?:\d{1,3}(?:,\d{3})+|\d+)\s?(?:万円|億円|円)"
    )

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self.policy = policy or PolicyConfig()

    def sanitize(self, text: str) -> SanitizationResult:
        if not isinstance(text, str):
            raise TypeError("Fail-closed: input must be a string.")

        working = text
        token_map: Dict[str, str] = {}
        reverse_map: Dict[str, str] = {}
        counts: Dict[str, int] = {}

        def _allocate(pii_type: str, original: str) -> str:
            if original in reverse_map:
                return reverse_map[original]
            idx = counts.get(pii_type, 0) + 1
            counts[pii_type] = idx
            placeholder = f"[{pii_type}_{idx}]"
            token_map[placeholder] = original
            reverse_map[original] = placeholder
            return placeholder

        if self.policy.mask_email:
            working = self._EMAIL_RE.sub(
                lambda m: _allocate("EMAIL", m.group(0)), working
            )
        if self.policy.mask_mynumber:
            working = self._MYNUMBER_RE.sub(
                lambda m: _allocate("ID_NUM", m.group(0)), working
            )
        if self.policy.mask_phone:
            working = self._PHONE_RE.sub(
                lambda m: _allocate("PHONE", m.group(0)), working
            )
        if self.policy.mask_postal_code:
            working = self._POSTAL_RE.sub(
                lambda m: _allocate("POSTAL", m.group(0)), working
            )
        if self.policy.mask_labeled_person:
            working = self._LABELED_PERSON_RE.sub(
                lambda m: f"{m.group(1)}{_allocate('PERSON', m.group(2).strip())}",
                working,
            )
        if self.policy.mask_labeled_address:
            working = self._LABELED_ADDRESS_RE.sub(
                lambda m: f"{m.group(1)}{_allocate('ADDRESS', m.group(2).strip())}",
                working,
            )
        if self.policy.mask_currency:
            working = self._CURRENCY_RE.sub(
                lambda m: _allocate("AMOUNT", m.group(0)), working
            )
        for label, pattern_str in self.policy.custom_patterns:
            compiled = re.compile(pattern_str)
            working = compiled.sub(
                lambda m, lbl=label: _allocate(lbl, m.group(0)), working
            )

        return SanitizationResult(
            sanitized_text=working,
            counts_by_type=counts,
            _token_map=token_map,
        )


class AuditLogger:
    """Append-only, SHA-256 hash-chained JSONL audit logger storing zero raw PII."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _hash_actor(actor_id: str) -> str:
        return hashlib.sha256(actor_id.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _compute_record_hash(payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return self.GENESIS_HASH
        lines = [
            ln.strip()
            for ln in self.log_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        if not lines:
            return self.GENESIS_HASH
        return json.loads(lines[-1])["record_hash"]

    def record(
        self,
        actor_id: str,
        action: str,
        result: SanitizationResult,
        status: str = "ALLOWED",
    ) -> dict:
        prev_hash = self._last_hash()
        body = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "actor_hash": self._hash_actor(actor_id),
            "action": action,
            "status": status,
            "total_masked": result.total_masked,
            "counts_by_type": result.counts_by_type,
            "prev_hash": prev_hash,
        }
        entry = {**body, "record_hash": self._compute_record_hash(body)}
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify_chain(self) -> Tuple[bool, int]:
        """Verifies integrity of the entire audit log. Returns (is_valid, record_count).

        Detects: edited fields, deleted lines (except the last one), reordered or
        inserted lines, and lines that are not valid JSON objects.
        Does not detect: deletion of trailing lines, a fully re-hashed chain
        (no secret key is used), or a missing log file (reported as (True, 0)).
        """
        if not self.log_path.exists():
            return True, 0
        lines = [
            ln.strip()
            for ln in self.log_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        expected_prev = self.GENESIS_HASH
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                return False, len(lines)
            if not isinstance(entry, dict):
                return False, len(lines)
            if entry.get("prev_hash") != expected_prev:
                return False, len(lines)
            recorded_hash = entry.get("record_hash")
            body = {k: v for k, v in entry.items() if k != "record_hash"}
            if self._compute_record_hash(body) != recorded_hash:
                return False, len(lines)
            expected_prev = recorded_hash
        return True, len(lines)
