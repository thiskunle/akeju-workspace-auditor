# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Workspace Auditor, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Google Workspace access. Writes are blocked at the HTTP layer, whatever the granted scopes allow."""
from datetime import datetime, timezone
from typing import Callable

from .checks import Forward, SharedFile, User

SCOPES = {
    "admin": ["https://www.googleapis.com/auth/admin.directory.user.readonly"],
    # Google's read-only Gmail scope would also expose every message. This one covers settings only.
    "gmail": ["https://www.googleapis.com/auth/gmail.settings.basic"],
    "drive": ["https://www.googleapis.com/auth/drive.metadata.readonly"],
}
PUBLIC_QUERY = "'me' in owners and trashed = false and (visibility = 'anyoneCanFind' or visibility = 'anyoneWithLink')"


class WriteBlocked(RuntimeError):
    pass


class ReadOnlyHttp:
    """Wraps the HTTP client and refuses anything except GET."""

    def __init__(self, http):
        self._http = http

    def request(self, uri, method="GET", *args, **kwargs):
        if method.upper() != "GET":
            raise WriteBlocked(f"Refused {method} {uri}: this tool is read-only.")
        return self._http.request(uri, method, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._http, name)


def _parse_time(value: str | None) -> datetime | None:
    if not value or value.startswith("1970-01-01"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


ServiceFactory = Callable[[str, str, str, list[str]], object]


class GoogleWorkspace:
    def __init__(self, service: ServiceFactory, admin_email: str):
        self._service = service
        self._admin = admin_email

    def users(self) -> list[User]:
        api = self._service("admin", "directory_v1", self._admin, SCOPES["admin"]).users()
        request = api.list(customer="my_customer", maxResults=500, orderBy="email")
        users = []
        while request is not None:
            page = request.execute()
            for u in page.get("users", []):
                users.append(User(email=u["primaryEmail"], is_admin=u.get("isAdmin", False), enrolled_2sv=u.get("isEnrolledIn2Sv", False),
                                  enforced_2sv=u.get("isEnforcedIn2Sv", False), suspended=u.get("suspended", False), last_login=_parse_time(u.get("lastLoginTime"))))
            request = api.list_next(request, page)
        return users

    def forwards(self, email: str) -> list[Forward]:
        settings = self._service("gmail", "v1", email, SCOPES["gmail"]).users().settings()
        found = []
        auto = settings.getAutoForwarding(userId="me").execute()
        if auto.get("enabled") and auto.get("emailAddress"):
            found.append(Forward("auto", auto["emailAddress"]))
        for f in settings.filters().list(userId="me").execute().get("filter", []):
            target = f.get("action", {}).get("forward")
            if target:
                found.append(Forward("filter", target))
        return found

    def public_files(self, email: str) -> list[SharedFile]:
        api = self._service("drive", "v3", email, SCOPES["drive"]).files()
        fields = "nextPageToken, files(name, webViewLink, permissions(type, allowFileDiscovery))"
        request = api.list(q=PUBLIC_QUERY, pageSize=1000, fields=fields)
        found = []
        while request is not None:
            page = request.execute()
            for f in page.get("files", []):
                discoverable = any(p.get("type") == "anyone" and p.get("allowFileDiscovery") for p in f.get("permissions", []))
                found.append(SharedFile(f.get("name", ""), f.get("webViewLink", ""), "anyoneCanFind" if discoverable else "anyoneWithLink"))
            request = api.list_next(request, page)
        return found


def service_account_factory(key_file: str) -> ServiceFactory:
    """Build API clients that act as a given user through domain-wide delegation."""
    import google_auth_httplib2
    import httplib2
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    def factory(api: str, version: str, subject: str, scopes: list[str]):
        credentials = service_account.Credentials.from_service_account_file(key_file, scopes=scopes, subject=subject)
        http = ReadOnlyHttp(google_auth_httplib2.AuthorizedHttp(credentials, http=httplib2.Http(timeout=30)))
        return build(api, version, http=http, cache_discovery=False, static_discovery=True)

    return factory
