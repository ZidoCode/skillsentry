from pathlib import Path

from skillsentry.discovery import discover, parse_frontmatter


def test_parse_frontmatter_scalars_and_lists():
    text = """---
name: demo-skill
description: does a thing
permissions:
  - network
  - exec
allowed-tools: [Read, Bash]
---

# Demo
"""
    data, _ = parse_frontmatter(text)
    assert data["name"] == "demo-skill"
    assert data["description"] == "does a thing"
    assert data["permissions"] == ["network", "exec"]
    assert data["allowed-tools"] == ["Read", "Bash"]


def test_parse_frontmatter_without_block():
    data, text = parse_frontmatter("# No frontmatter\n")
    assert data == {}
    assert text.startswith("# No")


def test_discover_finds_nested_manifests(tmp_path: Path):
    for name in ("alpha", "beta"):
        skill_dir = tmp_path / "skills" / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: %s\n---\n" % name)

    skills = discover(tmp_path)
    assert sorted(skill.name for skill in skills) == ["alpha", "beta"]


def test_discover_falls_back_to_directory(tmp_path: Path):
    (tmp_path / "run.py").write_text("print('hi')\n")
    skills = discover(tmp_path)
    assert len(skills) == 1
    assert any(ref.rel.endswith("run.py") for ref in skills[0].files)


def test_discover_skips_dependency_directories(tmp_path: Path):
    skill_dir = tmp_path / "demo"
    (skill_dir / "node_modules" / "pkg").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill_dir / "node_modules" / "pkg" / "evil.js").write_text("eval(x)\n")

    skill = discover(tmp_path)[0]
    assert not any("node_modules" in ref.rel for ref in skill.files)


def test_discover_honours_excludes(tmp_path: Path):
    skill_dir = tmp_path / "demo"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill_dir / "scripts").mkdir()
    (skill_dir / "scripts" / "install.sh").write_text("echo hi\n")

    skill = discover(tmp_path, excludes=["demo/scripts/*"])[0]
    assert not any("install.sh" in ref.rel for ref in skill.files)


def test_discover_skips_binary_files(tmp_path: Path):
    skill_dir = tmp_path / "demo"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill_dir / "blob.bin").write_bytes(b"\x00\x01\x02binary")

    skill = discover(tmp_path)[0]
    assert not any(ref.rel.endswith("blob.bin") for ref in skill.files)


def test_discover_skips_build_metadata(tmp_path: Path):
    skill_dir = tmp_path / "demo"
    (skill_dir / "demo.egg-info").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill_dir / "demo.egg-info" / "PKG-INFO").write_text("Metadata-Version: 2.1\n")

    skill = discover(tmp_path)[0]
    assert not any("egg-info" in ref.rel for ref in skill.files)


def test_single_file_scan(tmp_path: Path):
    script = tmp_path / "install.sh"
    script.write_text("echo hi\n")
    skills = discover(script)
    assert len(skills) == 1
    assert skills[0].files[0].rel == "install.sh"
