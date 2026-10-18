"""Detection rules.

Every rule is a small function that takes a :class:`~skillsentry.discovery.Skill`
and returns findings. Rules are intentionally static: skillsentry never runs the
code it inspects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Sequence

from .discovery import FileRef, Skill
from .models import Finding, Severity

# --------------------------------------------------------------------------- #
# patterns
# --------------------------------------------------------------------------- #

_REMOTE_PIPE = re.compile(
    r"(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:sh|bash|zsh|dash|python3?|node|perl|ruby|iex|powershell)\b",
    re.IGNORECASE,
)
_BASH_PROC = re.compile(r"\b(?:bash|sh)\s+<\(\s*(?:curl|wget)\b", re.IGNORECASE)
_IEX_PIPE = re.compile(
    r"\b(?:iwr|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,300}\|\s*iex\b",
    re.IGNORECASE,
)

_DYNAMIC_EXEC = (
    ("eval()", re.compile(r"(?<![\w.])eval\s*\(", re.IGNORECASE)),
    ("exec()", re.compile(r"(?<![\w.])exec\s*\(", re.IGNORECASE)),
    ("subprocess(shell=True)", re.compile(r"subprocess\.[A-Za-z_]+\([^)\n]{0,200}shell\s*=\s*True")),
    ("os.system()", re.compile(r"\bos\.system\s*\(")),
    ("child_process.exec", re.compile(r"\bchild_process\.(?:exec|execSync|spawnSync)\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
)

_CRED_PATHS = re.compile(
    r"(?:\.ssh/(?:id_[a-z0-9]+|config|known_hosts)"
    r"|\.aws/credentials|\.aws/config"
    r"|\.netrc|\.git-credentials"
    r"|\.docker/config\.json|\.kube/config"
    r"|Login Data|Cookies(?:\.sqlite)?|Library/Keychains"
    r"|\.config/gh/hosts\.yml|\.npmrc|\.pypirc|\.gnupg/)",
    re.IGNORECASE,
)
_ENV_SECRET = re.compile(
    r"(?:os\.environ(?:\.get)?\s*[\[(]\s*|getenv\s*\(\s*|process\.env\.)"
    r"['\"]?([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*)['\"]?",
    re.IGNORECASE,
)

_WEBHOOK = re.compile(
    r"https?://(?:discord(?:app)?\.com/api/webhooks"
    r"|hooks\.slack\.com"
    r"|api\.telegram\.org/bot"
    r"|webhook\.site|requestbin\.[a-z]+|pipedream\.net"
    r"|ngrok(?:-free)?\.(?:io|app)|burpcollaborator\.net|interact\.sh)",
    re.IGNORECASE,
)

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_ESC = re.compile(r"\\x[0-9a-fA-F]{2}")

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_INJECTION = (
    (
        "ignore previous instructions",
        re.compile(r"ignore (?:all )?(?:the )?(?:previous|prior|above) (?:instructions|prompts?|rules)", re.I),
    ),
    (
        "disregard the system prompt",
        re.compile(r"disregard (?:the )?(?:system|developer) (?:prompt|message|instructions)", re.I),
    ),
    (
        "do not tell the user",
        re.compile(r"do not (?:tell|inform|notify|warn|alert) the user", re.I),
    ),
    (
        "without asking the user",
        re.compile(r"without (?:asking|telling|informing) the user", re.I),
    ),
    ("exfiltrate", re.compile(r"\bexfiltrat(?:e|ion)\b", re.I)),
)
_HTML_COMMENT = re.compile(r"<!--(.{10,4000}?)-->", re.S)
_IMPERATIVE = re.compile(r"\b(?:run|execute|curl|wget|send|post|upload|delete|rm -rf)\b", re.I)

_RAW_MAIN = re.compile(r"https?://raw\.githubusercontent\.com/[^\s)\"']+/(?:main|master)/", re.I)
_UNPINNED_PIP = re.compile(
    r"\bpip3?\s+install\s+(?!-)([A-Za-z0-9_][A-Za-z0-9_.\-]*)(?![A-Za-z0-9_.\-=<>~+])"
)
_GIT_CLONE = re.compile(r"\bgit\s+clone\s+(?!.*(?:--branch|\.git#))\S*https?://", re.I)

_CAP_NETWORK = re.compile(r"https?://|\bfetch\s*\(|requests\.(?:get|post)|urlopen\s*\(|\bhttpx\.", re.I)
_CAP_EXEC = re.compile(r"subprocess\.|os\.system\s*\(|child_process\.|(?<![\w.])exec\s*\(|(?<![\w.])eval\s*\(")
_CAP_WRITE = re.compile(r"open\s*\([^)\n]{0,120}['\"][wa]\+?['\"]|writeFile(?:Sync)?\s*\(", re.I)

_CAPABILITY_ALIASES = {
    "network": {"network", "net", "http", "web", "internet", "outbound"},
    "exec": {"exec", "execute", "shell", "process", "bash", "system", "spawn"},
    "write": {"write", "filesystem", "fs", "files", "disk", "storage"},
    "secrets": {"secrets", "credentials", "env", "keys", "tokens"},
}

_HINT_BY_RULE = {
    "SE001": "Download the script, pin its hash, review it, then run the local copy.",
    "SE002": "Pass arguments as a list and drop shell=True / eval when input crosses a trust boundary.",
    "SE003": "Skills rarely need credential files. Ask the user to provide an explicit, scoped token instead.",
    "SE004": "Webhook destinations cannot be reviewed after the fact. Require a documented, owned endpoint.",
    "SE005": "Decode the payload and check it in; obfuscated blobs cannot be reviewed by the user.",
    "SE006": "Instructions hidden from the user are the core of an agent hijack. Reject the skill.",
    "SE007": "Pin to a tag or commit so an update cannot silently change what runs.",
    "SE008": "Declare every capability the skill uses in the permissions block.",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    check: Callable[[Skill], List[Finding]]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _evidence(match: "re.Match[str]", limit: int = 160) -> str:
    value = " ".join(match.group(0).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _finding(rule: str, severity: Severity, ref: FileRef, line: int, message: str, evidence: str) -> Finding:
    return Finding(
        rule=rule,
        severity=severity,
        path=ref.rel,
        line=line,
        message=message,
        evidence=evidence,
        hint=_HINT_BY_RULE.get(rule, ""),
    )


def _scan_text(rule: str, ref: FileRef, pattern: "re.Pattern[str]", message: str,
               severity: Severity, markdown_severity: "Severity | None" = None) -> List[Finding]:
    found: List[Finding] = []
    for match in pattern.finditer(ref.text):
        sev = severity
        if ref.kind == "markdown" and markdown_severity is not None:
            sev = markdown_severity
        found.append(_finding(rule, sev, ref, _line_of(ref.text, match.start()), message, _evidence(match)))
    return found


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #


def check_remote_pipe_exec(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        out += _scan_text(
            "SE001", ref, _REMOTE_PIPE,
            "remote download piped straight into an interpreter",
            Severity.HIGH, Severity.MEDIUM,
        )
        out += _scan_text(
            "SE001", ref, _BASH_PROC,
            "process substitution executes a remote download",
            Severity.HIGH, Severity.MEDIUM,
        )
        out += _scan_text(
            "SE001", ref, _IEX_PIPE,
            "PowerShell downloads and executes remote code",
            Severity.HIGH, Severity.MEDIUM,
        )
    return out


def check_dynamic_exec(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        if ref.kind not in ("script", "config", "other"):
            continue
        for label, pattern in _DYNAMIC_EXEC:
            for match in pattern.finditer(ref.text):
                out.append(
                    _finding(
                        "SE002",
                        Severity.HIGH if ref.kind == "script" else Severity.MEDIUM,
                        ref,
                        _line_of(ref.text, match.start()),
                        "dynamic code execution via %s" % label,
                        _evidence(match),
                    )
                )
    return out


def check_credential_access(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        out += _scan_text(
            "SE003", ref, _CRED_PATHS,
            "skill references a credential store",
            Severity.HIGH,
        )
        for match in _ENV_SECRET.finditer(ref.text):
            out.append(
                _finding(
                    "SE003",
                    Severity.MEDIUM,
                    ref,
                    _line_of(ref.text, match.start()),
                    "reads secret-bearing environment variable %s" % match.group(1),
                    _evidence(match),
                )
            )
    return out


def check_exfil_endpoint(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        has_secret = bool(_ENV_SECRET.search(ref.text) or _CRED_PATHS.search(ref.text))
        for match in _WEBHOOK.finditer(ref.text):
            endpoint = match.group(0)
            out.append(
                _finding(
                    "SE004",
                    Severity.CRITICAL if has_secret else Severity.HIGH,
                    ref,
                    _line_of(ref.text, match.start()),
                    "posts data to a personal webhook endpoint (%s)" % endpoint.split("//")[-1].split("/")[0],
                    _evidence(match),
                )
            )
    return out


def check_obfuscation(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        for match in _B64_BLOB.finditer(ref.text):
            out.append(
                _finding(
                    "SE005", Severity.MEDIUM, ref, _line_of(ref.text, match.start()),
                    "long base64-like blob (%d chars) — payload cannot be reviewed" % len(match.group(0)),
                    _evidence(match, 60),
                )
            )
        hex_hits = list(_HEX_ESC.finditer(ref.text))
        if len(hex_hits) >= 40:
            out.append(
                _finding(
                    "SE005", Severity.MEDIUM, ref, _line_of(ref.text, hex_hits[0].start()),
                    "high density of hex escapes (%d) suggests an encoded payload" % len(hex_hits),
                    _evidence(hex_hits[0], 60),
                )
            )
    return out


def check_hidden_instructions(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        seen_lines = set()
        for match in _INVISIBLE.finditer(ref.text):
            line = _line_of(ref.text, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            out.append(
                _finding(
                    "SE006", Severity.HIGH, ref, line,
                    "invisible or direction-override unicode (U+%04X)" % ord(match.group(0)),
                    "zero-width / bidi control character",
                )
            )
        if ref.kind == "markdown":
            comments = list(_HTML_COMMENT.finditer(ref.text))
            spans = [(match.start(), match.end()) for match in comments]
            for label, pattern in _INJECTION:
                for match in pattern.finditer(ref.text):
                    if any(start <= match.start() < end for start, end in spans):
                        continue
                    out.append(
                        _finding(
                            "SE006", Severity.HIGH, ref, _line_of(ref.text, match.start()),
                            "prompt-injection phrasing: %s" % label,
                            _evidence(match),
                        )
                    )
            for match in comments:
                body = match.group(1)
                if _IMPERATIVE.search(body):
                    out.append(
                        _finding(
                            "SE006", Severity.HIGH, ref, _line_of(ref.text, match.start()),
                            "HTML comment carries an instruction the rendered page hides",
                            _evidence(match, 120),
                        )
                    )
    return out


def check_unpinned_install(skill: Skill) -> List[Finding]:
    out: List[Finding] = []
    for ref in skill.files:
        if ref.kind != "markdown":
            continue
        out += _scan_text(
            "SE007", ref, _RAW_MAIN,
            "loads a file from a moving main branch",
            Severity.MEDIUM,
        )
        out += _scan_text(
            "SE007", ref, _GIT_CLONE,
            "clones a repository without pinning a branch, tag or commit",
            Severity.LOW,
        )
        for match in _UNPINNED_PIP.finditer(ref.text):
            out.append(
                _finding(
                    "SE007", Severity.LOW, ref, _line_of(ref.text, match.start()),
                    "installs package %s without a version pin" % match.group(1),
                    _evidence(match),
                )
            )
    return out


def _declared(frontmatter: dict) -> set:
    raw = frontmatter.get("permissions")
    values: Sequence[str]
    if isinstance(raw, list):
        values = [str(item) for item in raw]
    elif isinstance(raw, str):
        values = [part.strip() for part in raw.split(",")]
    else:
        return set()

    declared = set()
    for value in values:
        token = value.strip().lower()
        for capability, aliases in _CAPABILITY_ALIASES.items():
            if token == capability or token in aliases:
                declared.add(capability)
    return declared


def check_capability_drift(skill: Skill) -> List[Finding]:
    if "permissions" not in skill.frontmatter:
        return []
    declared = _declared(skill.frontmatter)

    used = {}
    for ref in skill.files:
        if ref.path == skill.entry:
            continue
        if _CAP_NETWORK.search(ref.text):
            used.setdefault("network", ref)
        if _CAP_EXEC.search(ref.text):
            used.setdefault("exec", ref)
        if _CAP_WRITE.search(ref.text):
            used.setdefault("write", ref)
        if _CRED_PATHS.search(ref.text) or _ENV_SECRET.search(ref.text):
            used.setdefault("secrets", ref)

    out: List[Finding] = []
    for capability, ref in sorted(used.items()):
        if capability in declared:
            continue
        out.append(
            _finding(
                "SE008", Severity.MEDIUM, ref, 1,
                "uses %s without declaring it in permissions" % capability,
                "declared: %s" % (", ".join(sorted(declared)) or "none"),
            )
        )
    return out


RULES: List[Rule] = [
    Rule("SE001", "remote-pipe-exec", Severity.HIGH,
         "Remote content piped into a shell or interpreter.", check_remote_pipe_exec),
    Rule("SE002", "dynamic-exec", Severity.HIGH,
         "eval/exec-style dynamic code execution.", check_dynamic_exec),
    Rule("SE003", "credential-access", Severity.HIGH,
         "Reads credential stores or secret environment variables.", check_credential_access),
    Rule("SE004", "exfil-endpoint", Severity.HIGH,
         "Sends data to personal webhook endpoints.", check_exfil_endpoint),
    Rule("SE005", "obfuscated-payload", Severity.MEDIUM,
         "Encoded or obfuscated content that cannot be reviewed.", check_obfuscation),
    Rule("SE006", "hidden-instructions", Severity.HIGH,
         "Instructions hidden from the user (bidi text, comments, injection phrasing).",
         check_hidden_instructions),
    Rule("SE007", "unpinned-install", Severity.LOW,
         "Installs or fetches code from a moving target.", check_unpinned_install),
    Rule("SE008", "capability-drift", Severity.MEDIUM,
         "Uses capabilities that the skill does not declare.", check_capability_drift),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}
