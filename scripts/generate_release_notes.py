#!/usr/bin/env python3
"""Generate release notes for a tagged DMARCView release.

The GitHub release workflow passes GitHub's generated notes as a fallback. When
``DEEPSEEK_API_KEY`` is configured, the script asks a DeepSeek chat model to turn
the commit/diff evidence into the same kind of prose-and-bullets release notes
used for the hand-written releases. If the API is missing or fails, the fallback
is used unchanged.

No network request is made without a key; the token is never logged.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_MODEL = "deepseek-chat"
MAX_COMMITS = 120
MAX_DIFFSTAT = 7000


def run_git(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], text=True, stderr=subprocess.DEVNULL, timeout=30
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def previous_tag(tag: str) -> Optional[str]:
    value = run_git("describe", "--tags", "--abbrev=0", "--match", "v*.*.*", f"{tag}^")
    return value or None


def evidence(tag: str, previous: Optional[str]) -> dict[str, str]:
    head = previous or tag
    if previous:
        commits = run_git(
            "log", "--no-merges", f"--max-count={MAX_COMMITS}", "--pretty=format:%h%x09%s", f"{previous}..{tag}"
        )
        diffstat = run_git("diff", "--stat", f"{previous}..{tag}")
        migrations = run_git("diff", "--name-only", f"{previous}..{tag}", "--", "backend/migrations/versions")
    else:
        commits = run_git("log", "--no-merges", f"--max-count={MAX_COMMITS}", "--pretty=format:%h%x09%s", tag)
        diffstat = run_git("show", "--stat", "--oneline", tag)
        migrations = run_git("ls-tree", "-r", "--name-only", tag, "--", "backend/migrations/versions")
    return {
        "previous": previous or "",
        "commits": commits[:12000],
        "diffstat": diffstat[:MAX_DIFFSTAT],
        "migrations": migrations,
        "head": head,
    }


def prompt(tag: str, info: dict[str, str], fallback: str) -> str:
    version = tag.removeprefix("v")
    previous = info["previous"] or "(none — first release)"
    migrations = info["migrations"].strip() or "(none)"
    return f"""You are the technical writer for DMARCView, a self-hosted DMARC aggregate and
TLS-RPT reporting dashboard. Write the GitHub release body for {tag}.

Use ONLY the evidence below. Do not invent features, issue numbers, test counts, links,
or claims. If a change is not user-visible, omit it or group it under maintenance. The
workflow appends the container image, digest and Full Changelog link; do not include those.

Structure:
## DMARCView {version} — <short title>
A 1–2 paragraph summary in prose.
### Highlights
- 3–8 bullets covering the most useful changes.
### Upgrade notes
- Migration/configuration/operational notes. State explicitly when no database migration
  is required. Use the migration list evidence.
### Verification
- The backend test suite and frontend build passed before publishing. Do not invent a
  test count.

Formatting rules:
- GitHub-flavored Markdown.
- No manual line breaks. Each paragraph and each bullet must be on one line; use blank
  lines only between blocks.
- Do not wrap lines at a character limit.
- No surrounding code fence.
- Do not include a horizontal rule, image line, digest, or Full Changelog section.

Version: {tag}
Previous release: {previous}

Commit subjects (hash<TAB>subject):
{info['commits'] or '(no commit list available)'}

Diffstat:
{info['diffstat'] or '(no diffstat available)'}

Migration files:
{migrations}

GitHub-generated fallback notes (may contain noisy PR metadata; use only as supporting
evidence):
{fallback[:12000]}
"""


def normalise_markdown(text: str) -> str:
    """Remove manual wraps from paragraphs and bullets, preserving code blocks."""
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if len(lines) > 1:
            text = "\n".join(lines[1:-1]).strip()
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    block: list[str] = []
    fence: Optional[str] = None
    list_re = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
    heading_re = re.compile(r"^\s*#{1,6}\s+")
    fence_re = re.compile(r"^\s*(```|~~~)")

    def flush() -> None:
        nonlocal block
        if not block:
            return
        first = block[0].strip()
        if heading_re.match(first):
            out.append(first)
            for line in block[1:]:
                if line.strip():
                    out.append(line.strip())
        elif first.startswith(("---", "***", "___")):
            out.append(first)
        else:
            list_rows = [i for i, line in enumerate(block) if list_re.match(line)]
            if list_rows:
                prefix = [line.strip() for line in block[: list_rows[0]] if line.strip()]
                if prefix:
                    out.append(" ".join(prefix))
                    out.append("")
                items: list[str] = []
                for line in block[list_rows[0]:]:
                    value = line.strip()
                    if not value:
                        continue
                    if list_re.match(line):
                        items.append(value)
                    elif items:
                        items[-1] = f"{items[-1]} {value}"
                    else:
                        items.append(value)
                out.extend(items)
            else:
                out.append(" ".join(line.strip() for line in block if line.strip()))
        block = []

    for line in lines:
        if fence is not None:
            out.append(line)
            if fence_re.match(line) and line.strip().startswith(fence):
                fence = None
            continue
        if fence_re.match(line):
            flush()
            fence = line.strip()[:3]
            out.append(line)
            continue
        if not line.strip():
            flush()
            if out and out[-1] != "":
                out.append("")
            continue
        block.append(line)
    flush()
    while out and out[-1] == "":
        out.pop()
    while out and out[0] == "":
        out.pop(0)
    result: list[str] = []
    for line in out:
        if line == "" and result and result[-1] == "":
            continue
        result.append(line)
    return "\n".join(result).strip() + "\n"


def deepseek(prompt_text: str) -> Optional[str]:
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not key:
        print("DEEPSEEK_API_KEY not set; using GitHub fallback notes.", file=sys.stderr)
        return None
    url = os.environ.get("DEEPSEEK_API_URL", DEFAULT_URL).strip() or DEFAULT_URL
    model = os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You write concise, accurate software release notes. "
                        "Follow the requested Markdown structure exactly."
                    ),
                },
                {"role": "user", "content": prompt_text},
            ],
            "temperature": 0.25,
            "max_tokens": 1800,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return str(content)
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode("utf-8", "replace")
        print(f"DeepSeek HTTP {exc.code}: {detail[:300]}", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError) as exc:
        print(f"DeepSeek request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    return None


def strip_appended(body: str) -> str:
    """Remove the metadata the release workflow appends itself."""
    kept: list[str] = []
    skip = False
    for line in body.splitlines():
        lowered = line.strip().lower()
        if lowered.startswith(("**container image:**", "**digest:**", "**full changelog**:")):
            skip = True
            continue
        if line.startswith("## "):
            skip = False
        if not skip:
            kept.append(line)
    return "\n".join(kept).strip() + "\n"


def clean_ai(text: Optional[str], fallback: str, tag: str) -> str:
    if not text:
        body = strip_appended(normalise_markdown(fallback))
        if body.strip():
            return body
        return f"## DMARCView {tag.removeprefix('v')}\n\nMaintenance and dependency release. See the commit history for details.\n"
    body = strip_appended(normalise_markdown(text))
    if len(body) < 120 or not body.startswith("## "):
        print("DeepSeek returned unusable notes; using GitHub fallback.", file=sys.stderr)
        return strip_appended(normalise_markdown(fallback))
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--fallback", required=True, help="GitHub-generated notes file")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    fallback = Path(args.fallback).read_text().strip()
    prev = previous_tag(args.tag)
    info = evidence(args.tag, prev)
    generated = deepseek(prompt(args.tag, info, fallback))
    body = clean_ai(generated, fallback, args.tag)
    Path(args.output).write_text(body)
    print(f"release notes written to {args.output} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
