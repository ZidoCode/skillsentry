"""Renderers: text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Dict, List

from .models import Finding, Severity
from .rules import RULES
from .scan import ScanResult

_FORMATS = ("text", "json", "sarif")


def _safe_uri(path: str) -> str:
    return path.replace("\\", "/")


def render_text(result: ScanResult) -> str:
    counts = result.counts()
    lines: List[str] = []
    lines.append(
        "skillsentry — %d skill(s), %d file(s) scanned, %d rule(s)"
        % (len(result.skills), result.files_scanned, result.rules_run)
    )
    total = len(result.findings)
    summary = "findings: %d (critical=%d high=%d medium=%d low=%d)" % (
        total,
        counts["critical"],
        counts["high"],
        counts["medium"],
        counts["low"],
    )
    if result.suppressed:
        summary += ", suppressed=%d" % result.suppressed
    lines.append(summary)

    for finding in result.findings:
        lines.append("")
        lines.append(
            "  [%s] %s %s:%d — %s"
            % (finding.severity.value.upper(), finding.rule, finding.path, finding.line, finding.message)
        )
        if finding.evidence:
            lines.append("         %s" % finding.evidence)
        if finding.hint:
            lines.append("         fix: %s" % finding.hint)

    if not total:
        lines.append("")
        lines.append("  no findings — every scanned skill is clean at this level")
    return "\n".join(lines)


def as_dict(result: ScanResult) -> Dict[str, object]:
    return {
        "tool": "skillsentry",
        "root": result.root,
        "skills": [skill.name for skill in result.skills],
        "files_scanned": result.files_scanned,
        "rules_run": result.rules_run,
        "suppressed": result.suppressed,
        "summary": result.counts(),
        "findings": [finding.as_dict() for finding in result.findings],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(as_dict(result), indent=2, ensure_ascii=False)


def render_sarif(result: ScanResult) -> str:
    used_rules = {finding.rule for finding in result.findings}
    rules = [
        {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _sarif_level(rule.severity)},
            "helpUri": "https://github.com/ZidoCode/skillsentry#%s" % rule.id.lower(),
        }
        for rule in RULES
        if rule.id in used_rules or not used_rules
    ]

    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule,
                "level": _sarif_level(finding.severity),
                "message": {"text": "%s — %s" % (finding.message, finding.hint) if finding.hint else finding.message},
                "partialFingerprints": {"skillsentry/v1": finding.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _safe_uri(finding.path)},
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillsentry",
                        "informationUri": "https://github.com/ZidoCode/skillsentry",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }[severity]


def render(result: ScanResult, fmt: str = "text") -> str:
    if fmt == "text":
        return render_text(result)
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    raise ValueError("unknown format %r (use %s)" % (fmt, ", ".join(_FORMATS)))


def formats() -> tuple:
    return _FORMATS
