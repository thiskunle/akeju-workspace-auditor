# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Workspace Auditor, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
from dataclasses import asdict, replace

from . import ATTRIBUTION, __author__, __version__
from .checks import SEVERITIES, Finding, Result


def redact_email(text: str) -> str:
    if "@" not in text:
        return text
    local, domain = text.rsplit("@", 1)
    return f"user-{hashlib.sha256(local.lower().encode()).hexdigest()[:8]}@{domain}"


def redacted(findings: list[Finding]) -> list[Finding]:
    return [replace(f, subject=redact_email(f.subject)) for f in findings]


def summary(result: Result) -> str:
    counts = [f"{sum(f.severity == s for f in result.findings)} {s}" for s in SEVERITIES]
    return f"{result.users_checked} active accounts checked. Findings: {', '.join(counts)}."


def to_text(result: Result) -> str:
    lines = ["Google Workspace security audit", summary(result), ""]
    for f in result.findings:
        lines += [f"[{f.severity.upper()}] {f.check}: {f.subject}", f"    {f.title}", f"    Fix: {f.fix}"]
    if result.errors:
        lines += ["", "Checks that could not finish, so these accounts are not fully audited:"] + [f"    {e}" for e in result.errors]
    lines += ["", ATTRIBUTION]
    return "\n".join(lines) + "\n"


def to_markdown(result: Result) -> str:
    lines = ["# Google Workspace security audit", "", f"**{summary(result)}**", "", "| Severity | Check | Account | Finding | Fix |", "|---|---|---|---|---|"]
    lines += [f"| {f.severity} | {f.check} | {f.subject} | {f.title} | {f.fix} |" for f in result.findings]
    if result.errors:
        lines += ["", "## Checks that could not finish", ""] + [f"- {e}" for e in result.errors]
    lines += ["", f"*{ATTRIBUTION}*"]
    return "\n".join(lines) + "\n"


def to_json(result: Result) -> str:
    return json.dumps({"summary": summary(result), "users_checked": result.users_checked, "findings": [asdict(f) for f in result.findings],
                       "errors": result.errors, "generator": {"name": "akeju-workspace-auditor", "version": __version__, "author": __author__}}, indent=2) + "\n"


RENDER = {"text": to_text, "markdown": to_markdown, "json": to_json}
