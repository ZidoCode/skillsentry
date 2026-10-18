"""Renderers: text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List
from urllib.parse import quote

from . import __version__
from .models import Finding, Severity
from .rules import RULES
from .scan import ScanResult

_FORMATS = ("text", "json", "sarif")


def _safe_uri(path: str) -> str:
    return quote(path.replace("\\", "/"), safe="/")


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
    if result.skipped_files:
        lines.append(
            "  skipped %d file(s) that could not be read as text: %s"
            % (len(result.skipped_files), ", ".join(result.skipped_files[:5]))
        )

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
        "skipped_files": result.skipped_files,
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

    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    workspace = Path(os.getcwd()).resolve()

    results = []
    for finding in result.findings:
        uri = _workspace_relative(finding.path, result.root, workspace)
        entry = {
            "ruleId": finding.rule,
            "level": _sarif_level(finding.severity),
            "message": {"text": "%s — %s" % (finding.message, finding.hint) if finding.hint else finding.message},
            "partialFingerprints": {"skillsentry/v1": finding.fingerprint},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _safe_uri(uri),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, finding.line)},
                    }
                }
            ],
        }
        if finding.rule in rule_index:
            entry["ruleIndex"] = rule_index[finding.rule]
        results.append(entry)

    invocation = {"executionSuccessful": True}
    if result.skipped_files:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "warning",
                "message": {"text": "not scanned (binary, unreadable or larger than 8 MiB): %s" % rel},
                "descriptor": {"id": "SKIPPED_FILE"},
            }
            for rel in result.skipped_files
        ]

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillsentry",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/ZidoCode/skillsentry",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "skillsentry"},
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": workspace.as_uri() + "/"},
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def _workspace_relative(path: str, scan_root: str, workspace: Path) -> str:
    """Express a finding path relative to the checkout root when possible."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(scan_root) / candidate
    try:
        return candidate.resolve().relative_to(workspace).as_posix()
    except (ValueError, OSError):
        return path.replace("\\", "/")


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
