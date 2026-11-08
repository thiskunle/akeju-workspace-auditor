# akeju-workspace-auditor

**Created by Adekunle Akeju, founder of GramByte Technologies Inc.**

A read-only audit of a Google Workspace organization. It flags the settings attackers rely on.

| Check | Severity |
|---|---|
| Super admin without two-step verification | Critical |
| User without two-step verification | High |
| Mail forwarding or filters sending to an outside address | High |
| Files searchable on the public web | High |
| Two-step verification optional, or too many super admins | Medium |
| Files open to anyone with the link | Medium |
| Dormant or never-used accounts | Low |

See a sample report without any credentials:

```
pip install .
akeju-workspace-audit --demo
```

## Run it on your organization

Only audit organizations you administer or have written permission to review.

1. Create a Google Cloud service account and enable the Admin SDK, Gmail and Drive APIs.
2. In the Admin console, grant it domain-wide delegation for the scopes below.
3. Run:

```
akeju-workspace-audit --key-file key.json --admin you@company.com --domain company.com --format markdown --output audit.md --redact
```

| Scope | Why |
|---|---|
| `admin.directory.user.readonly` | Account list and two-step status |
| `gmail.settings.basic` | Forwarding and filter settings |
| `drive.metadata.readonly` | File names and sharing, never contents |

**About the Gmail scope.** Google has no read-only scope for mail settings alone. `gmail.readonly` would also expose every message, so this tool uses the settings scope instead, and refuses all non-GET requests at the HTTP layer. A test proves a delete call never reaches the network.

Treat the key file as a powerful credential. Delete the service account when the audit ends.

## Test status

Audit rules and the Google client are tested against recorded-format API responses using Google's own client library. It has not yet been run against a live Workspace organization.

## License and credit

AGPL-3.0-or-later, with an attribution requirement. See [NOTICE.md](NOTICE.md). Copyright (c) 2026 Adekunle Akeju.
