"""Active Directory client tests using an in-memory LDAP double."""

from __future__ import annotations

import pytest

from conftest import FakeLDAPConnection, ad_user
from license_cleanup.ad_client import ADAuthError, ADClient, ADConnectionError, ADSearchError, escape_filter_value
from license_cleanup.models import ADStatus

DIRECTORY = [
    ad_user("alice", "alice@example.com"),
    ad_user("bob", "bob@example.com", disabled=True),
    ad_user("carol", "carol.new@example.com", proxies=["SMTP:carol.new@example.com", "smtp:carol@example.com"]),
    ad_user("dup1", "dup@example.com"),
    ad_user("dup2", "dup@example.com"),
    ad_user("dave", "dave.smith@example.com"),
]


def make_client(ad_config, conn: FakeLDAPConnection) -> ADClient:
    client = ADClient(ad_config, "svc-ldap-reader@corp.example.test", "fake-password",
                      connection_factory=lambda *_: conn)
    client.connect()
    return client


def test_enabled_user(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("Alice@Example.com ")
    assert result.status is ADStatus.ENABLED
    assert result.sam_account_name == "alice"
    assert result.matched_attribute == "mail" and result.strong_match


def test_disabled_user_uses_accountdisable_flag(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("bob@example.com")
    assert result.status is ADStatus.DISABLED


def test_changed_email_found_via_proxy_addresses(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("carol@example.com")
    assert result.status is ADStatus.ENABLED
    assert result.matched_attribute == "proxyAddresses"


def test_domain_alias(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("alice@old-example.com")
    assert result.status is ADStatus.ENABLED and result.strong_match
    assert "alias" in result.message


def test_not_found_is_not_disabled(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("nobody@example.com")
    assert result.status is ADStatus.NOT_FOUND


def test_external_contractor(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("eve@contractor.example.net")
    assert result.status is ADStatus.EXTERNAL


def test_multiple_matches(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("dup@example.com")
    assert result.status is ADStatus.MULTIPLE


def test_samaccountname_fallback_is_weak(ad_config) -> None:
    result = make_client(ad_config, FakeLDAPConnection(DIRECTORY)).lookup("dave@another.example.org")
    assert result.status is ADStatus.ENABLED
    assert result.strong_match is False


def test_ad_unavailable(ad_config) -> None:
    with pytest.raises(ADConnectionError):
        make_client(ad_config, FakeLDAPConnection(DIRECTORY, fail_open=True))


def test_ad_authentication_failure(ad_config) -> None:
    with pytest.raises(ADAuthError) as exc:
        make_client(ad_config, FakeLDAPConnection(DIRECTORY, bind_ok=False))
    assert "fake-password" not in str(exc.value)


def test_search_failure_raises(ad_config) -> None:
    client = make_client(ad_config, FakeLDAPConnection(DIRECTORY, fail_search=True))
    with pytest.raises(ADSearchError):
        client.lookup("alice@example.com")


def test_ldap_injection_is_escaped(ad_config) -> None:
    conn = FakeLDAPConnection(DIRECTORY)
    client = make_client(ad_config, conn)
    result = client.lookup("*)(uid=*))(|(mail=*@example.com")
    assert result.status is ADStatus.NOT_FOUND
    assert all("*)(uid=*)" not in f for f in conn.filters)
    assert escape_filter_value("a*b(c)\\") == "a\\2ab\\28c\\29\\5c"


def test_lookup_is_cached_but_can_be_forced(ad_config) -> None:
    conn = FakeLDAPConnection(DIRECTORY)
    client = make_client(ad_config, conn)
    client.lookup("alice@example.com")
    count = len(conn.filters)
    client.lookup("alice@example.com")
    assert len(conn.filters) == count
    client.lookup("alice@example.com", use_cache=False)
    assert len(conn.filters) > count


def test_real_connection_factory_enforces_ldaps_and_read_only(ad_config) -> None:
    import ssl

    from license_cleanup.ad_client import _default_connection_factory

    conn = _default_connection_factory(ad_config, "svc@corp.example.test", "fake")  # not opened: no network
    assert conn.server.ssl is True
    assert conn.server.tls.validate == ssl.CERT_REQUIRED
    assert conn.read_only is True
