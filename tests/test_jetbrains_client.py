"""JetBrains API client tests (all HTTP mocked with `responses`)."""

from __future__ import annotations

import pytest
import requests
import responses
from responses import matchers

from conftest import BASE_URL, FAKE_CUSTOMER, FAKE_TOKEN, license_json
from license_cleanup.jetbrains_client import (
    InventoryIncompleteError,
    JetBrainsAPIError,
    JetBrainsAuthError,
    JetBrainsClient,
    JetBrainsSchemaError,
    RevokeOutcome,
    parse_license,
)
from license_cleanup.models import AssigneeType

LICENSES = f"{BASE_URL}/customer/licenses"


def client(**kwargs) -> JetBrainsClient:
    kwargs.setdefault("sleep", lambda _s: None)
    kwargs.setdefault("page_size", 2)
    return JetBrainsClient(BASE_URL, FAKE_TOKEN, FAKE_CUSTOMER, **kwargs)


def add_pages(assigned: bool, pages: list[list[dict]], total: int | None) -> None:
    for number, items in enumerate(pages, start=1):
        headers = {"X-Total-Count": str(total)} if total is not None else {}
        responses.get(
            LICENSES, json=items, headers=headers,
            match=[matchers.query_param_matcher({"page": str(number), "perPage": "2",
                                                 "assigned": "true" if assigned else "false"})],
        )


def test_rejects_plain_http() -> None:
    with pytest.raises(ValueError):
        JetBrainsClient("http://insecure.test", FAKE_TOKEN, FAKE_CUSTOMER)


def test_tls_verification_is_always_enabled() -> None:
    assert client().session.verify is True
    assert client(ca_bundle="/etc/ssl/corp.pem").session.verify == "/etc/ssl/corp.pem"


@responses.activate
def test_sends_documented_auth_headers() -> None:
    responses.get(f"{BASE_URL}/token", json={"type": "CUSTOMER", "role": "ADMIN", "teams": []},
                  match=[matchers.header_matcher({"X-Api-Key": FAKE_TOKEN, "X-Customer-Code": FAKE_CUSTOMER})])
    assert client().get_token_info()["role"] == "ADMIN"


@responses.activate
def test_api_authentication_failure_raises_auth_error_without_leaking_token() -> None:
    responses.get(f"{BASE_URL}/token", status=401, json={"code": "UNAUTHORIZED", "description": "Invalid token"})
    with pytest.raises(JetBrainsAuthError) as exc:
        client().get_token_info()
    assert exc.value.status == 401
    assert FAKE_TOKEN not in str(exc.value)


@responses.activate
def test_forbidden_is_auth_error() -> None:
    responses.get(f"{BASE_URL}/token", status=403, json={"code": "FORBIDDEN", "description": "no"})
    with pytest.raises(JetBrainsAuthError):
        client().get_token_info()


@responses.activate
def test_pagination_collects_all_pages_for_assigned_and_unassigned() -> None:
    add_pages(True, [[license_json("L1"), license_json("L2")], [license_json("L3")]], total=3)
    add_pages(False, [[license_json("L4", email=None)]], total=1)
    licenses, metas = client().list_licenses()
    assert [lic.license_id for lic in licenses] == ["L1", "L2", "L3", "L4"]
    assert all(m.complete for m in metas)
    assert licenses[3].assignee_type is AssigneeType.NONE


@responses.activate
def test_incomplete_pagination_aborts() -> None:
    add_pages(True, [[license_json("L1"), license_json("L2")], [license_json("L3")]], total=5)
    with pytest.raises(InventoryIncompleteError):
        client().list_licenses()


@responses.activate
def test_missing_total_header_aborts_when_required() -> None:
    add_pages(True, [[license_json("L1")]], total=None)
    with pytest.raises(InventoryIncompleteError):
        client().list_licenses()


@responses.activate
def test_duplicate_license_ids_abort() -> None:
    add_pages(True, [[license_json("L1")]], total=1)
    add_pages(False, [[license_json("L1", email=None)]], total=1)
    with pytest.raises(InventoryIncompleteError):
        client().list_licenses()


@responses.activate
def test_rate_limiting_is_retried_with_retry_after() -> None:
    sleeps: list[float] = []
    responses.get(f"{BASE_URL}/products", status=429, headers={"Retry-After": "3"})
    responses.get(f"{BASE_URL}/products", json=[{"code": "II", "name": "IntelliJ IDEA Ultimate"}])
    products = client(sleep=sleeps.append).list_products()
    assert products == {"II": "IntelliJ IDEA Ultimate"}
    assert sleeps == [3.0]


@responses.activate
def test_server_errors_are_retried_then_fail() -> None:
    for _ in range(3):
        responses.get(f"{BASE_URL}/products", status=503)
    with pytest.raises(JetBrainsAPIError):
        client(max_retries=2).list_products()
    assert len(responses.calls) == 3


@responses.activate
def test_network_errors_are_retried() -> None:
    responses.get(f"{BASE_URL}/products", body=requests.ConnectionError("boom"))
    responses.get(f"{BASE_URL}/products", json=[])
    assert client().list_products() == {}


@responses.activate
def test_unexpected_schema_raises() -> None:
    responses.get(LICENSES, json={"unexpected": True}, headers={"X-Total-Count": "1"})
    with pytest.raises(JetBrainsSchemaError):
        client().list_licenses()


def test_parse_license_rejects_missing_fields() -> None:
    with pytest.raises(JetBrainsSchemaError):
        parse_license({"product": {"code": "II"}})
    with pytest.raises(JetBrainsSchemaError):
        parse_license({"licenseId": "L1"})
    bad = license_json()
    bad["lastSeen"]["lastSeenDate"] = "not-a-date"
    with pytest.raises(JetBrainsSchemaError):
        parse_license(bad)


def test_parse_server_assignee() -> None:
    raw = license_json()
    raw["assignee"] = {"type": "SERVER", "serverType": "LICENSE_VAULT", "uid": "x"}
    assert parse_license(raw).assignee_type is AssigneeType.SERVER


@responses.activate
def test_revoke_uses_license_id_only_and_reports_success() -> None:
    responses.post(f"{BASE_URL}/customer/licenses/revoke", json={"licenseIds": ["L1"]},
                   match=[matchers.query_param_matcher({"licenseId": "L1"})])
    result = client().revoke_license("L1")
    assert result.outcome is RevokeOutcome.REVOKED
    assert "email" not in responses.calls[0].request.url


@responses.activate
def test_revoke_recently_assigned_is_rejected() -> None:
    responses.post(f"{BASE_URL}/customer/licenses/revoke", status=400,
                   json={"code": "RECENTLY_ASSIGNED_LICENSE_IS_NOT_AVAILABLE_FOR_REVOKE", "description": "too new"})
    result = client().revoke_license("L1")
    assert result.outcome is RevokeOutcome.REJECTED
    assert result.error_code == "RECENTLY_ASSIGNED_LICENSE_IS_NOT_AVAILABLE_FOR_REVOKE"


@responses.activate
def test_revoke_timeout_is_uncertain_and_not_retried() -> None:
    responses.post(f"{BASE_URL}/customer/licenses/revoke", body=requests.Timeout("slow"))
    result = client().revoke_license("L1")
    assert result.outcome is RevokeOutcome.UNCERTAIN
    assert len(responses.calls) == 1


@responses.activate
def test_revoke_5xx_is_uncertain_and_not_retried() -> None:
    responses.post(f"{BASE_URL}/customer/licenses/revoke", status=502)
    assert client().revoke_license("L1").outcome is RevokeOutcome.UNCERTAIN
    assert len(responses.calls) == 1


@responses.activate
def test_get_license_404_returns_none() -> None:
    responses.get(f"{LICENSES}/L9", status=404)
    assert client().get_license("L9") is None


@responses.activate
def test_get_never_follows_redirects_with_the_api_key() -> None:
    responses.get(f"{BASE_URL}/token", status=302, headers={"Location": "https://attacker.example.test/collect"})
    responses.get("https://attacker.example.test/collect", json={})
    with pytest.raises(JetBrainsAPIError, match="redirect"):
        client().get_token_info()
    assert all("attacker" not in call.request.url for call in responses.calls)


@responses.activate
def test_revoke_redirect_is_uncertain_and_not_followed() -> None:
    responses.post(f"{BASE_URL}/customer/licenses/revoke", status=307,
                   headers={"Location": "https://attacker.example.test/collect"})
    result = client().revoke_license("L1")
    assert result.outcome is RevokeOutcome.UNCERTAIN
    assert len(responses.calls) == 1
