# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Workspace Auditor, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit logic. It knows nothing about Google's API, so every rule can be tested with plain data."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

SEVERITIES = ("critical", "high", "medium", "low")
MAX_SUPER_ADMINS = 3


@dataclass(frozen=True)
class User:
    email: str
    is_admin: bool = False
    enrolled_2sv: bool = False
    enforced_2sv: bool = False
    suspended: bool = False
    last_login: datetime | None = None


@dataclass(frozen=True)
class Forward:
    kind: str  # "auto" or "filter"
    target: str


@dataclass(frozen=True)
class SharedFile:
    name: str
    url: str
    visibility: str


class Directory(Protocol):
    def users(self) -> list[User]: ...
    def forwards(self, email: str) -> list[Forward]: ...
    def public_files(self, email: str) -> list[SharedFile]: ...


@dataclass(frozen=True)
class Finding:
    severity: str
    check: str
    subject: str
    title: str
    fix: str


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    users_checked: int = 0


def is_external(address: str, domains: set[str]) -> bool:
    domain = address.rsplit("@", 1)[-1].strip().lower()
    return domain not in domains and not any(domain.endswith("." + d) for d in domains)


def audit(client: Directory, domains: list[str], now: datetime, dormant_days: int = 90) -> Result:
    internal = {d.lower() for d in domains}
    result = Result()
    users = client.users()
    active = [u for u in users if not u.suspended]
    result.users_checked = len(active)
    add = result.findings.append

    admins = [u for u in active if u.is_admin]
    if len(admins) > MAX_SUPER_ADMINS:
        add(Finding("medium", "Admin accounts", "organization", f"{len(admins)} super admins", f"Keep {MAX_SUPER_ADMINS} or fewer and give others narrower admin roles."))

    for user in active:
        if not user.enrolled_2sv:
            severity = "critical" if user.is_admin else "high"
            who = "Super admin has" if user.is_admin else "User has"
            add(Finding(severity, "Two-step verification", user.email, f"{who} no two-step verification", "Enroll this account and enforce two-step verification."))
        elif not user.enforced_2sv:
            add(Finding("medium", "Two-step verification", user.email, "Two-step verification is optional", "Enforce it in the Admin console so it cannot be turned off."))

        if user.last_login is None:
            add(Finding("low", "Dormant accounts", user.email, "Account has never signed in", "Suspend it if it is not needed."))
        elif (now - user.last_login).days >= dormant_days:
            add(Finding("low", "Dormant accounts", user.email, f"No sign-in for {(now - user.last_login).days} days", "Suspend it if it is not needed."))

        try:
            for forward in client.forwards(user.email):
                if is_external(forward.target, internal):
                    how = "Auto-forwarding" if forward.kind == "auto" else "A mail filter forwards"
                    add(Finding("high", "Mail forwarding", user.email, f"{how} to external address {forward.target}", "Confirm it is legitimate. Attackers use this to keep reading mail after a break-in."))
        except Exception as exc:  # A failed check must be visible, not read as clean.
            result.errors.append(f"Could not read mail settings for {user.email}: {type(exc).__name__}")

        try:
            files = client.public_files(user.email)
            public = [f for f in files if f.visibility == "anyoneCanFind"]
            links = [f for f in files if f.visibility == "anyoneWithLink"]
            if public:
                add(Finding("high", "File sharing", user.email, f"{len(public)} file(s) are searchable on the public web", "Restrict them unless they are meant to be public."))
            if links:
                add(Finding("medium", "File sharing", user.email, f"{len(links)} file(s) open to anyone with the link", "Review them and restrict any that hold business data."))
        except Exception as exc:
            result.errors.append(f"Could not read Drive sharing for {user.email}: {type(exc).__name__}")

    result.findings.sort(key=lambda f: SEVERITIES.index(f.severity))
    return result
