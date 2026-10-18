"""Scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

from .discovery import Skill, discover
from .models import Finding, Severity
from .rules import RULES, RULES_BY_ID, Rule

DEFAULT_IGNORE_FILE = ".skillsentryignore"


@dataclass
class ScanResult:
    root: str
    skills: List[Skill] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    suppressed: int = 0
    rules_run: int = 0

    @property
    def files_scanned(self) -> int:
        seen = set()
        for skill in self.skills:
            for ref in skill.files:
                seen.add(ref.rel)
        return len(seen)

    def counts(self) -> dict:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


def load_ignore(path: str | Path) -> Set[str]:
    """Read an ignore file.

    Each non-comment line is either a full fingerprint
    (``SE001:scripts/install.sh:12:ab12cd34ef56``) or a ``RULE:path`` prefix.
    """

    target = Path(path).expanduser()
    if not target.exists():
        return set()
    entries: Set[str] = set()
    for raw in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.add(line)
    return entries


def _is_ignored(finding: Finding, entries: Set[str]) -> bool:
    if finding.fingerprint in entries:
        return True
    if "%s:%s" % (finding.rule, finding.path) in entries:
        return True
    return False


def _select_rules(names: Optional[Sequence[str]]) -> List[Rule]:
    if not names:
        return list(RULES)
    selected: List[Rule] = []
    unknown: List[str] = []
    for name in names:
        key = name.strip().upper()
        rule = RULES_BY_ID.get(key)
        if rule is None:
            for candidate in RULES:
                if candidate.title == name.strip().lower():
                    rule = candidate
                    break
        if rule is None:
            unknown.append(name)
        elif rule not in selected:
            selected.append(rule)
    if unknown:
        raise ValueError("unknown rule(s): %s (run 'skillsentry rules')" % ", ".join(unknown))
    return selected


def scan(
    path: str | Path,
    excludes: Sequence[str] = (),
    ignore: Optional[Set[str]] = None,
    rule_names: Optional[Sequence[str]] = None,
) -> ScanResult:
    """Run every selected rule over the skills found under *path*."""

    rules = _select_rules(rule_names)
    ignore = ignore or set()
    skills = discover(path, excludes)

    findings: List[Finding] = []
    for skill in skills:
        for rule in rules:
            findings.extend(rule.check(skill))

    result = ScanResult(root=str(Path(path).expanduser()), skills=skills, rules_run=len(rules))
    seen: Set[str] = set()
    for finding in findings:
        fingerprint = finding.fingerprint
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if _is_ignored(finding, ignore):
            result.suppressed += 1
            continue
        result.findings.append(finding)

    result.findings.sort(key=lambda item: (-item.severity.rank, item.path, item.line, item.rule))
    return result
