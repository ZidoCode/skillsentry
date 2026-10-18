"""Core data model."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(
                "unknown severity %r (use low, medium, high or critical)" % value
            ) from exc


_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    """One rule hit."""

    rule: str
    severity: Severity
    path: str
    line: int
    message: str
    evidence: str = ""
    hint: str = ""

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha1(
            ("%s|%s|%s" % (self.rule, self.path, self.evidence)).encode("utf-8", "replace")
        ).hexdigest()[:12]
        return "%s:%s:%d:%s" % (self.rule, self.path, self.line, digest)

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "hint": self.hint,
            "fingerprint": self.fingerprint,
        }
