"""Read-only Active Directory lookups over LDAPS.

Matching order (strongest first):

1. ``mail`` equals the license email
2. ``userPrincipalName`` equals the license email
3. ``proxyAddresses`` contains ``smtp:<email>`` (aliases, renamed mailboxes)
4. Steps 1-3 repeated for configured domain aliases (e.g. a pre-rebrand domain)
5. ``sAMAccountName`` equals the email local part (weak; always manual review)

The first tier that returns results wins. More than one entry in the winning
tier is reported as ``MULTIPLE_MATCHES``. All user input is escaped with
:func:`ldap3.utils.conv.escape_filter_chars` to prevent LDAP injection.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any, Callable, Protocol

from .config_manager import ADConfig
from .models import ADLookupResult, ADStatus

log = logging.getLogger(__name__)

UF_ACCOUNTDISABLE = 0x0002
ATTRIBUTES = ["sAMAccountName", "userPrincipalName", "mail", "userAccountControl", "proxyAddresses"]
# LDAP result code for sizeLimitExceeded: more entries exist than we asked for.
LDAP_SIZE_LIMIT_EXCEEDED = 4


class ADConnectionError(Exception):
    """The directory server could not be reached or the TLS handshake failed."""


class ADAuthError(Exception):
    """The service account could not bind (wrong credentials, locked, expired)."""


class ADSearchError(Exception):
    """A search failed for a reason other than "no results"."""


class LDAPConnection(Protocol):
    """Subset of :class:`ldap3.Connection` used by this module (for test doubles)."""

    result: dict[str, Any]
    response: list[dict[str, Any]] | None

    def open(self) -> Any: ...
    def bind(self) -> bool: ...
    def search(self, search_base: str, search_filter: str, search_scope: Any = ..., attributes: Any = ...,
               size_limit: int = ..., time_limit: int = ...) -> bool: ...
    def unbind(self) -> Any: ...


def escape_filter_value(value: str) -> str:
    """Escape a value for use in an LDAP filter (RFC 4515)."""
    from ldap3.utils.conv import escape_filter_chars

    return escape_filter_chars(value)


def normalize_email(email: str) -> str:
    """Normalise an email address for comparison (trim + casefold)."""
    return (email or "").strip().casefold()


def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return "" if value is None else str(value)


def _default_connection_factory(cfg: ADConfig, user: str, password: str) -> LDAPConnection:
    """Create a real ldap3 connection with mandatory certificate validation."""
    from ldap3 import SIMPLE, Connection, Server, Tls

    # version=None makes ldap3 use ssl.create_default_context() (TLS 1.2+, CA validation).
    # With CERT_REQUIRED ldap3 also checks that the certificate matches cfg.server.
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=None,
        ca_certs_file=cfg.ca_certs_file or None,
        sni=cfg.server,
    )
    server = Server(cfg.server, port=cfg.port, use_ssl=True, tls=tls, connect_timeout=cfg.connect_timeout_seconds,
                    get_info=None)
    return Connection(
        server,
        user=user,
        password=password,
        authentication=SIMPLE,
        read_only=True,
        receive_timeout=int(cfg.search_timeout_seconds),
        raise_exceptions=False,
        auto_bind=False,
    )


class ADClient:
    """Look up licensed users in Active Directory (read-only)."""

    def __init__(
        self,
        cfg: ADConfig,
        bind_user: str,
        bind_password: str,
        connection_factory: Callable[[ADConfig, str, str], LDAPConnection] | None = None,
    ) -> None:
        self.cfg = cfg
        self._bind_user = bind_user
        self._bind_password = bind_password
        self._factory = connection_factory or _default_connection_factory
        self._conn: LDAPConnection | None = None
        self._cache: dict[str, ADLookupResult] = {}
        self.external_domains = {d.strip().casefold().lstrip("@") for d in cfg.external_domains}
        self.domain_aliases = {k.strip().casefold(): v.strip().casefold() for k, v in cfg.email_domain_aliases.items()}

    # ---------------------------------------------------------- connection
    def connect(self) -> None:
        """Open an LDAPS connection and bind. Raises ADConnectionError / ADAuthError."""
        try:
            conn = self._factory(self.cfg, self._bind_user, self._bind_password)
            conn.open()
        except Exception as exc:  # ldap3 raises many socket/TLS exception types
            raise ADConnectionError(f"Cannot connect to {self.cfg.server}:{self.cfg.port} over LDAPS: {type(exc).__name__}") from None
        try:
            ok = conn.bind()
        except Exception as exc:
            raise ADConnectionError(f"LDAPS bind to {self.cfg.server} failed: {type(exc).__name__}") from None
        if not ok:
            desc = (conn.result or {}).get("description", "invalidCredentials")
            raise ADAuthError(f"Active Directory bind failed for the service account ({desc})")
        self._conn = conn
        log.info("Connected to Active Directory %s:%s (LDAPS)", self.cfg.server, self.cfg.port)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:  # pragma: no cover - best effort
                log.debug("LDAP unbind failed (ignored)")
            self._conn = None

    def __enter__(self) -> "ADClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def health_check(self) -> None:
        """Run a minimal search under the base DN to prove read access works."""
        self._search("(objectClass=domain)", size_limit=1, scope_override="BASE")

    # -------------------------------------------------------------- search
    def _scope(self, override: str | None = None) -> Any:
        from ldap3 import BASE, LEVEL, SUBTREE

        return {"SUBTREE": SUBTREE, "LEVEL": LEVEL, "BASE": BASE}[(override or self.cfg.search_scope).upper()]

    def _search(self, ldap_filter: str, size_limit: int = 5, scope_override: str | None = None) -> list[dict[str, Any]]:
        if self._conn is None:
            raise ADConnectionError("Not connected to Active Directory")
        try:
            self._conn.search(
                search_base=self.cfg.base_dn,
                search_filter=ldap_filter,
                search_scope=self._scope(scope_override),
                attributes=ATTRIBUTES,
                size_limit=size_limit,
                time_limit=int(self.cfg.search_timeout_seconds),
            )
        except Exception as exc:
            raise ADSearchError(f"LDAP search failed: {type(exc).__name__}") from None
        result_code = (self._conn.result or {}).get("result", 0)
        if result_code not in (0, LDAP_SIZE_LIMIT_EXCEEDED):
            raise ADSearchError(f"LDAP search failed: {(self._conn.result or {}).get('description', result_code)}")
        entries = [e for e in (self._conn.response or []) if e.get("type") == "searchResEntry"]
        if result_code == LDAP_SIZE_LIMIT_EXCEEDED and len(entries) < 2:
            # Treat as "more than one" so the caller flags it for manual review.
            entries = entries + [{"type": "searchResEntry", "attributes": {}}] * (2 - len(entries))
        return entries

    @staticmethod
    def _user_filter(attribute: str, value: str) -> str:
        return f"(&(objectCategory=person)(objectClass=user)({attribute}={escape_filter_value(value)}))"

    def _candidate_emails(self, email: str) -> list[str]:
        emails = [email]
        local, _, domain = email.partition("@")
        alias_target = self.domain_aliases.get(domain)
        if alias_target and alias_target != domain:
            emails.append(f"{local}@{alias_target}")
        return emails

    def lookup(self, email: str, use_cache: bool = True) -> ADLookupResult:
        """Look up one email address. Never raises for "not found"; raises on connectivity loss.

        ``use_cache=False`` forces a fresh directory query (used for revalidation).
        """
        normalized = normalize_email(email)
        if use_cache and normalized in self._cache:
            return self._cache[normalized]
        result = self._lookup_uncached(normalized)
        self._cache[normalized] = result
        return result

    def _lookup_uncached(self, email: str) -> ADLookupResult:
        if not email or "@" not in email:
            return ADLookupResult(email=email, status=ADStatus.NOT_FOUND, message="License assignee has no valid email")

        tiers: list[tuple[str, str, bool]] = []
        for candidate in self._candidate_emails(email):
            tiers += [
                ("mail", candidate, True),
                ("userPrincipalName", candidate, True),
                ("proxyAddresses", f"smtp:{candidate}", True),
            ]
        if self.cfg.allow_samaccountname_fallback:
            tiers.append(("sAMAccountName", email.partition("@")[0], False))

        for attribute, value, strong in tiers:
            entries = self._search(self._user_filter(attribute, value))
            if not entries:
                continue
            if len(entries) > 1:
                return ADLookupResult(
                    email=email, status=ADStatus.MULTIPLE, matched_attribute=attribute, strong_match=strong,
                    message=f"{len(entries)} AD accounts match {attribute}",
                )
            attrs = entries[0].get("attributes", {}) or {}
            uac_raw = _first(attrs.get("userAccountControl"))
            try:
                uac = int(uac_raw)
            except (TypeError, ValueError):
                return ADLookupResult(
                    email=email, status=ADStatus.ERROR, matched_attribute=attribute, strong_match=strong,
                    sam_account_name=_first(attrs.get("sAMAccountName")),
                    user_principal_name=_first(attrs.get("userPrincipalName")),
                    message="userAccountControl missing or unreadable (check service account read permissions)",
                )
            status = ADStatus.DISABLED if uac & UF_ACCOUNTDISABLE else ADStatus.ENABLED
            message = "" if strong else "Matched only by sAMAccountName = email local part (weak match)"
            if strong and value.casefold().removeprefix("smtp:") != email:
                message = "Matched via configured domain alias"
            return ADLookupResult(
                email=email, status=status, matched_attribute=attribute, strong_match=strong,
                sam_account_name=_first(attrs.get("sAMAccountName")),
                user_principal_name=_first(attrs.get("userPrincipalName")),
                message=message,
            )

        domain = email.partition("@")[2]
        if domain in self.external_domains:
            return ADLookupResult(email=email, status=ADStatus.EXTERNAL,
                                  message="External/contractor domain: no AD account expected")
        return ADLookupResult(email=email, status=ADStatus.NOT_FOUND, message="No matching AD account")
