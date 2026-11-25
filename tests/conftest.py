"""Shared fixtures. All identities, tokens and hosts are fictional."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from license_cleanup.config_manager import (
    ADConfig,
    AppConfig,
    ExecutionConfig,
    Exclusions,
    PolicyConfig,
    SafetyConfig,
)
from license_cleanup.models import AssigneeType, License

NOW = datetime(2026, 11, 1, 2, 30, tzinfo=timezone.utc)
FAKE_TOKEN = "fake-token-0000-not-real"
FAKE_CUSTOMER = "FAKE-CUSTOMER-123"
BASE_URL = "https://jetbrains.api.test/api/v1"


def make_license(
    license_id: str = "LIC0000001",
    email: str = "alice@example.com",
    product_code: str = "II",
    product_name: str = "IntelliJ IDEA Ultimate",
    last_seen: datetime | None = datetime(2026, 10, 1, tzinfo=timezone.utc),
    assigned: datetime | None = datetime(2025, 1, 1, tzinfo=timezone.utc),
    assignee_type: AssigneeType = AssigneeType.USER,
    offline: bool | None = False,
    team_id: int | None = 1,
    team_name: str = "Engineering",
) -> License:
    return License(
        license_id=license_id,
        product_code=product_code,
        product_name=product_name,
        team_id=team_id,
        team_name=team_name,
        assignee_type=assignee_type,
        assignee_email=email if assignee_type is AssigneeType.USER else "",
        assignee_name="Test User" if assignee_type is AssigneeType.USER else "",
        is_available_to_assign=assignee_type is AssigneeType.NONE,
        is_suspended=False,
        is_trial=False,
        last_seen_date=last_seen,
        last_assignment_date=assigned,
        is_offline_code_generated=offline,
        license_type="SUBSCRIPTION",
    )


def license_json(
    license_id: str = "LIC0000001",
    email: str | None = "alice@example.com",
    product_code: str = "II",
    last_seen: str | None = "2026-10-01T00:00:00Z",
    assigned: str | None = "2025-01-01T00:00:00Z",
) -> dict[str, Any]:
    """A LicenseResponse object shaped exactly like the documented OpenAPI schema."""
    return {
        "assignee": None if email is None else {"email": email, "name": "Test User", "type": "USER"},
        "domain": "example.com",
        "isAvailableToAssign": email is None,
        "isSuspended": False,
        "isTransferableBetweenTeams": True,
        "isTrial": False,
        "lastSeen": {"isOfflineCodeGenerated": False, "lastAssignmentDate": assigned, "lastSeenDate": last_seen},
        "licenseId": license_id,
        "perpetual": None,
        "product": {"code": product_code, "name": {"II": "IntelliJ IDEA Ultimate", "PC": "PyCharm Professional",
                                                   "ALL": "All Products Pack"}.get(product_code, product_code)},
        "subscription": {"isAutomaticallyRenewed": True, "isOutdated": False, "subscriptionPackRef": "PACK-1",
                         "validUntilDate": "2027-06-30T00:00:00Z"},
        "team": {"id": 1, "name": "Engineering"},
    }


@pytest.fixture
def policy() -> PolicyConfig:
    return PolicyConfig()


@pytest.fixture
def safety() -> SafetyConfig:
    return SafetyConfig(max_revocations=20, hard_max_revocations=50, max_revocation_percent=50)


@pytest.fixture
def ad_config() -> ADConfig:
    return ADConfig(domain="corp.example.test", server="dc01.corp.example.test", port=636,
                    base_dn="DC=corp,DC=example,DC=test", ca_certs_file=None,
                    external_domains=["contractor.example.net"], email_domain_aliases={"old-example.com": "example.com"})


@pytest.fixture
def app_config(ad_config: ADConfig, safety: SafetyConfig) -> AppConfig:
    return AppConfig(execution=ExecutionConfig(), active_directory=ad_config, safety=safety, exclusions=Exclusions())


class FakeLDAPConnection:
    """In-memory stand-in for ldap3.Connection.

    ``directory`` is a list of user attribute dicts. The fake understands the
    filters produced by ADClient: ``(&(objectCategory=person)(objectClass=user)(attr=value))``.
    """

    def __init__(self, directory: list[dict[str, Any]], *, bind_ok: bool = True, fail_open: bool = False,
                 fail_search: bool = False) -> None:
        self.directory = directory
        self.bind_ok = bind_ok
        self.fail_open = fail_open
        self.fail_search = fail_search
        self.result: dict[str, Any] = {"result": 0}
        self.response: list[dict[str, Any]] | None = []
        self.filters: list[str] = []
        self.writes = 0

    def open(self) -> None:
        if self.fail_open:
            raise OSError("connection refused")

    def bind(self) -> bool:
        if not self.bind_ok:
            self.result = {"result": 49, "description": "invalidCredentials"}
        return self.bind_ok

    def unbind(self) -> None:
        pass

    def search(self, search_base: str, search_filter: str, search_scope: Any = None, attributes: Any = None,
               size_limit: int = 0, time_limit: int = 0) -> bool:
        from ldap3.utils.conv import unescape_filter_chars

        if self.fail_search:
            raise OSError("socket closed")
        self.filters.append(search_filter)
        self.result = {"result": 0}
        if search_filter == "(objectClass=domain)":
            self.response = [{"type": "searchResEntry", "attributes": {}}]
            return True
        inner = search_filter.rsplit("(", 1)[1].rstrip(")")
        attr, _, value = inner.partition("=")
        raw = unescape_filter_chars(value)
        value = (raw.decode() if isinstance(raw, bytes) else raw).casefold()
        matches = []
        for user in self.directory:
            values = user.get(attr)
            values = values if isinstance(values, list) else [values]
            if any(v is not None and str(v).casefold() == value for v in values):
                matches.append({"type": "searchResEntry", "attributes": user})
        self.response = matches
        return bool(matches)

    # Any write method would indicate a bug: the client must be read-only.
    def modify(self, *a: Any, **k: Any) -> None:  # pragma: no cover
        self.writes += 1
        raise AssertionError("AD write attempted")


def ad_user(sam: str, mail: str, disabled: bool = False, upn: str | None = None,
            proxies: list[str] | None = None) -> dict[str, Any]:
    return {
        "sAMAccountName": sam,
        "userPrincipalName": upn or f"{sam}@corp.example.test",
        "mail": mail,
        "userAccountControl": 514 if disabled else 512,
        "proxyAddresses": proxies or [f"SMTP:{mail}"],
    }
