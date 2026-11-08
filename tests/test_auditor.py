# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Workspace Auditor, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import json
from datetime import datetime, timedelta, timezone

import pytest
from googleapiclient.discovery import build
from googleapiclient.http import HttpMockSequence

from akeju_workspace_audit import checks, cli, report
from akeju_workspace_audit.checks import Forward, SharedFile, User
from akeju_workspace_audit.google_client import GoogleWorkspace, ReadOnlyHttp, WriteBlocked

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)
SAFE = dict(enrolled_2sv=True, enforced_2sv=True, last_login=NOW)


class Fake:
    def __init__(self, users, forwards=None, files=None):
        self._users, self._forwards, self._files = users, forwards or {}, files or {}

    def users(self):
        return self._users

    def forwards(self, email):
        value = self._forwards.get(email, [])
        if isinstance(value, Exception):
            raise value
        return value

    def public_files(self, email):
        value = self._files.get(email, [])
        if isinstance(value, Exception):
            raise value
        return value


def run(client):
    return checks.audit(client, ["acme.com"], NOW)


def test_clean_account_has_no_findings():
    assert run(Fake([User("a@acme.com", **SAFE)])).findings == []


def test_admin_without_2sv_is_critical_and_user_is_high():
    r = run(Fake([User("adm@acme.com", is_admin=True, last_login=NOW), User("u@acme.com", last_login=NOW)]))
    assert [f.severity for f in r.findings] == ["critical", "high"]


def test_optional_2sv_is_medium():
    assert run(Fake([User("a@acme.com", enrolled_2sv=True, last_login=NOW)])).findings[0].severity == "medium"


@pytest.mark.parametrize("target,count", [("x@gmail.com", 1), ("x@acme.com", 0), ("x@mail.acme.com", 0), ("x@acme.com.evil.net", 1), ("x@notacme.com", 1), ("X@ACME.COM", 0)])
def test_forwarding_external_detection(target, count):
    r = run(Fake([User("a@acme.com", **SAFE)], forwards={"a@acme.com": [Forward("auto", target)]}))
    assert len(r.findings) == count


def test_filter_forward_is_reported():
    r = run(Fake([User("a@acme.com", **SAFE)], forwards={"a@acme.com": [Forward("filter", "x@gmail.com")]}))
    assert "filter" in r.findings[0].title and r.findings[0].severity == "high"


def test_file_sharing_severity():
    files = [SharedFile("a", "u", "anyoneCanFind"), SharedFile("b", "u", "anyoneWithLink"), SharedFile("c", "u", "anyoneWithLink")]
    r = run(Fake([User("a@acme.com", **SAFE)], files={"a@acme.com": files}))
    assert [(f.severity, f.title[0]) for f in r.findings] == [("high", "1"), ("medium", "2")]


def test_dormant_and_never_signed_in():
    r = run(Fake([User("old@acme.com", enrolled_2sv=True, enforced_2sv=True, last_login=NOW - timedelta(days=120)), User("new@acme.com", enrolled_2sv=True, enforced_2sv=True)]))
    titles = " ".join(f.title for f in r.findings)
    assert "120 days" in titles and "never" in titles


def test_too_many_super_admins():
    users = [User(f"a{i}@acme.com", is_admin=True, **SAFE) for i in range(4)]
    assert run(Fake(users)).findings[0].title == "4 super admins"


def test_suspended_accounts_are_skipped():
    r = run(Fake([User("gone@acme.com", suspended=True)]))
    assert r.findings == [] and r.users_checked == 0


def test_api_failure_is_reported_not_treated_as_clean():
    u = User("a@acme.com", **SAFE)
    r = run(Fake([u], forwards={u.email: PermissionError("no")}, files={u.email: PermissionError("no")}))
    assert len(r.errors) == 2
    assert "not fully audited" in report.to_text(r)


def test_redaction_hides_names_and_is_stable():
    f = [checks.Finding("high", "c", "jane@acme.com", "t", "x")]
    out = report.redacted(f)[0].subject
    assert "jane" not in out and out.endswith("@acme.com") and out == report.redacted(f)[0].subject


def test_reports_credit_the_author():
    r = checks.Result()
    assert "Adekunle Akeju" in report.to_text(r) and "Adekunle Akeju" in report.to_markdown(r)
    assert json.loads(report.to_json(r))["generator"]["author"] == "Adekunle Akeju"


def test_demo_runs_and_exits_nonzero(capsys):
    assert cli.main(["--demo"]) == 1
    assert "CRITICAL" in capsys.readouterr().out


def test_real_run_needs_credentials():
    with pytest.raises(SystemExit):
        cli.main([])


def ok(body):
    return ({"status": "200"}, json.dumps(body).encode())


def workspace(api, version, responses):
    http = ReadOnlyHttp(HttpMockSequence(responses))
    service = build(api, version, http=http, developerKey="x", cache_discovery=False, static_discovery=True)
    return GoogleWorkspace(lambda *_: service, "admin@acme.com"), http


def test_google_users_follow_pages_and_map_fields():
    gw, _ = workspace("admin", "directory_v1", [
        ok({"users": [{"primaryEmail": "a@acme.com", "isAdmin": True, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": False, "lastLoginTime": "2026-11-01T10:00:00.000Z"}], "nextPageToken": "p2"}),
        ok({"users": [{"primaryEmail": "b@acme.com", "lastLoginTime": "1970-01-01T00:00:00.000Z", "suspended": True}]}),
    ])
    users = gw.users()
    assert [u.email for u in users] == ["a@acme.com", "b@acme.com"]
    assert users[0].is_admin and users[0].enrolled_2sv and not users[0].enforced_2sv and users[0].last_login.year == 2026
    assert users[1].last_login is None and users[1].suspended


def test_google_forwards_reads_auto_and_filters():
    gw, _ = workspace("gmail", "v1", [
        ok({"enabled": True, "emailAddress": "x@gmail.com"}),
        ok({"filter": [{"action": {"forward": "y@gmail.com"}}, {"action": {"addLabelIds": ["A"]}}]}),
    ])
    assert gw.forwards("a@acme.com") == [Forward("auto", "x@gmail.com"), Forward("filter", "y@gmail.com")]


def test_google_files_tell_searchable_from_link():
    gw, _ = workspace("drive", "v3", [ok({"files": [
        {"name": "a", "webViewLink": "u", "permissions": [{"type": "anyone", "allowFileDiscovery": True}]},
        {"name": "b", "webViewLink": "v", "permissions": [{"type": "anyone", "allowFileDiscovery": False}]},
    ]})])
    assert [f.visibility for f in gw.public_files("a@acme.com")] == ["anyoneCanFind", "anyoneWithLink"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post"])
def test_writes_are_refused_before_reaching_the_network(method):
    class Boom:
        def request(self, *a, **k):
            raise AssertionError("reached the network")
    with pytest.raises(WriteBlocked):
        ReadOnlyHttp(Boom()).request("https://x", method)


def test_update_call_through_the_real_client_is_blocked():
    _, http = workspace("admin", "directory_v1", [ok({})])
    service = build("admin", "directory_v1", http=http, developerKey="x", cache_discovery=False, static_discovery=True)
    with pytest.raises(WriteBlocked):
        service.users().delete(userKey="a@acme.com").execute()
