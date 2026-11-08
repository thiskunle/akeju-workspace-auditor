# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Workspace Auditor, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import pathlib
import sys
from datetime import datetime, timedelta, timezone

from . import ATTRIBUTION, report
from .checks import Forward, SharedFile, User, audit


class Demo:
    """Made-up organization, so the report can be seen without any credentials."""

    def __init__(self, now):
        self.now = now

    def users(self):
        return [User("founder@example.com", is_admin=True, enrolled_2sv=False, last_login=self.now),
                User("sales@example.com", enrolled_2sv=True, enforced_2sv=False, last_login=self.now),
                User("old-contractor@example.com", enrolled_2sv=True, enforced_2sv=True, last_login=self.now - timedelta(days=200))]

    def forwards(self, email):
        return [Forward("filter", "someone@outside.example.net")] if email.startswith("sales") else []

    def public_files(self, email):
        return [SharedFile("Client list.xlsx", "https://drive.example/1", "anyoneWithLink")] if email.startswith("founder") else []


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="akeju-workspace-audit", description=f"Read-only Google Workspace security audit. {ATTRIBUTION}.")
    parser.add_argument("--key-file", help="service account JSON key with domain-wide delegation")
    parser.add_argument("--admin", help="super admin email to read the directory as")
    parser.add_argument("--domain", action="append", default=[], help="domain you treat as internal; repeat for several")
    parser.add_argument("--format", choices=report.RENDER, default="text")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--redact", action="store_true", help="replace account names with hashes in the report")
    parser.add_argument("--dormant-days", type=int, default=90)
    parser.add_argument("--demo", action="store_true", help="run against made-up data")
    parser.add_argument("--version", action="version", version=ATTRIBUTION)
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc)
    if args.demo:
        client, domains = Demo(now), ["example.com"]
    else:
        if not (args.key_file and args.admin and args.domain):
            parser.error("--key-file, --admin and --domain are required unless you use --demo")
        from .google_client import GoogleWorkspace, service_account_factory
        client, domains = GoogleWorkspace(service_account_factory(args.key_file), args.admin), args.domain

    result = audit(client, domains, now, args.dormant_days)
    if args.redact:
        result.findings = report.redacted(result.findings)
    text = report.RENDER[args.format](result)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
    return 1 if any(f.severity in ("critical", "high") for f in result.findings) else 0
