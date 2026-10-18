"""Find agent skills on disk and read their files."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

MAX_FILE_BYTES = 1_500_000

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
}

MARKDOWN_SUFFIXES = {".md", ".markdown"}
SCRIPT_SUFFIXES = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".rb",
    ".go",
    ".rs",
    ".php",
}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".txt"}

MANIFEST_NAMES = ("skill.md", "skill.markdown")


@dataclass
class FileRef:
    """A text file that belongs to a skill."""

    path: Path
    rel: str
    kind: str  # markdown | script | config | other
    text: str


@dataclass
class Skill:
    """One skill: a directory with a SKILL.md, or a loose file/directory."""

    root: Path
    name: str
    entry: Path
    frontmatter: Dict[str, object] = field(default_factory=dict)
    files: List[FileRef] = field(default_factory=list)

    @property
    def entry_rel(self) -> str:
        for ref in self.files:
            if ref.path == self.entry:
                return ref.rel
        return self.entry.name


def parse_frontmatter(text: str) -> Tuple[Dict[str, object], str]:
    """Parse the small YAML subset used by SKILL.md: scalars and ``- item`` lists."""

    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = None
    for index in range(1, len(lines)):
        if lines[index].strip() in ("---", "..."):
            end = index
            break
    if end is None:
        return {}, text

    data: Dict[str, object] = {}
    current_key: Optional[str] = None
    for raw in lines[1:end]:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_key is not None:
            bucket = data.get(current_key)
            if not isinstance(bucket, list):
                bucket = []
                data[current_key] = bucket
            bucket.append(stripped[2:].strip().strip("'\""))
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        current_key = key
        if not value:
            data[key] = []
        elif value.startswith("[") and value.endswith("]"):
            data[key] = [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
        else:
            data[key] = value.strip("'\"")
    return data, text


def _kind_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in MARKDOWN_SUFFIXES:
        return "markdown"
    if suffix in SCRIPT_SUFFIXES:
        return "script"
    if suffix in CONFIG_SUFFIXES:
        return "config"
    return "other"


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def _excluded(rel: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*"):
            return True
    return False


def _in_skipped_dir(rel: str) -> bool:
    parts = Path(rel).parts[:-1]
    return any(part in SKIP_DIRS for part in parts)


def _build_skill(
    root: Path,
    entry: Optional[Path],
    base: Path,
    excludes: Sequence[str],
    single_file: Optional[Path] = None,
) -> Skill:
    frontmatter: Dict[str, object] = {}
    if entry is not None:
        entry_text = _read_text(entry) or ""
        frontmatter, _ = parse_frontmatter(entry_text)

    name = frontmatter.get("name")
    if not isinstance(name, str) or not name.strip():
        name = root.name

    candidates: List[Path]
    if single_file is not None:
        candidates = [single_file]
    else:
        candidates = sorted(p for p in root.rglob("*") if p.is_file())

    files: List[FileRef] = []
    for path in candidates:
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            rel = path.name
        if _excluded(rel, excludes) or _in_skipped_dir(rel):
            continue
        text = _read_text(path)
        if text is None:
            continue
        files.append(FileRef(path=path, rel=rel, kind=_kind_for(path), text=text))

    return Skill(root=root, name=str(name), entry=entry or root, frontmatter=frontmatter, files=files)


def discover(path: str | Path, excludes: Sequence[str] = ()) -> List[Skill]:
    """Discover skills under *path*.

    A skill is a directory containing SKILL.md. When no manifest is found the
    given directory is treated as a single skill so plain script folders and
    plugin repos can be scanned too.
    """

    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(str(target))

    if target.is_file():
        base = target.parent
        if target.name.lower() in MANIFEST_NAMES:
            return [_build_skill(target.parent, target, base, excludes)]
        return [_build_skill(target.parent, None, base, excludes, single_file=target)]

    base = target
    manifests = [
        p
        for p in sorted(target.rglob("*"))
        if p.is_file() and p.name.lower() in MANIFEST_NAMES
    ]
    skills: List[Skill] = []
    for manifest in manifests:
        try:
            rel = manifest.relative_to(base).as_posix()
        except ValueError:
            rel = manifest.name
        if _excluded(rel, excludes) or _in_skipped_dir(rel):
            continue
        skills.append(_build_skill(manifest.parent, manifest, base, excludes))

    if not skills:
        skills.append(_build_skill(target, None, base, excludes))
    return skills
