"""Client for the official JetBrains Account REST API.

Only endpoints, headers and fields documented in the official OpenAPI
specification (https://account.jetbrains.com/openapi) are used:

* ``GET  /token``                          - identify the token's organization/team and role
* ``GET  /products``                       - product dictionary (code -> name)
* ``GET  /customer/licenses``              - organization license list (paged)
* ``GET  /customer/teams/{teamId}/licenses`` - team license list (paged)
* ``GET  /customer/licenses/{licenseId}``  - single license details
* ``POST /customer/licenses/revoke?licenseId=...`` - revoke one assigned license

Authentication uses the ``X-Api-Key`` and ``X-Customer-Code`` headers.
Paged responses carry ``Link`` and ``X-Total-Count`` headers.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

import requests

from .models import AssigneeType, License, parse_timestamp

log = logging.getLogger(__name__)

RECENTLY_ASSIGNED_ERROR = "RECENTLY_ASSIGNED_LICENSE_IS_NOT_AVAILABLE_FOR_REVOKE"


class JetBrainsAPIError(Exception):
    """Generic API failure. ``status`` is the HTTP status (0 for network errors)."""

    def __init__(self, message: str, status: int = 0, code: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class JetBrainsAuthError(JetBrainsAPIError):
    """HTTP 401/403: invalid/expired token, wrong customer code or missing permission."""


class JetBrainsSchemaError(JetBrainsAPIError):
    """The API returned data that does not match the documented schema."""


class InventoryIncompleteError(JetBrainsAPIError):
    """Pagination finished but the inventory does not match the reported total."""


class RevokeOutcome(str, Enum):
    REVOKED = "REVOKED"          # API confirmed the license id in the response
    REJECTED = "REJECTED"        # API answered with a definite error (nothing revoked)
    UNCERTAIN = "UNCERTAIN"      # Timeout / 5xx / connection error: state unknown


@dataclass
class RevokeResponse:
    outcome: RevokeOutcome
    revoked_ids: list[str]
    status: int
    error_code: str = ""
    message: str = ""


@dataclass
class InventoryMeta:
    """Completeness metadata collected while paging through the inventory."""

    pages_fetched: int = 0
    reported_total: int | None = None
    collected: int = 0
    complete: bool = False


def _safe_error_text(response: requests.Response) -> tuple[str, str]:
    """Extract ``code``/``description`` from the documented Error schema."""
    try:
        body = response.json()
    except ValueError:
        return "", f"HTTP {response.status_code}"
    if isinstance(body, dict):
        return str(body.get("code") or ""), str(body.get("description") or body.get("code") or f"HTTP {response.status_code}")
    return "", f"HTTP {response.status_code}"


def parse_license(raw: Any) -> License:
    """Convert one ``LicenseResponse`` JSON object into a :class:`License`.

    Raises :class:`JetBrainsSchemaError` when required fields are missing or
    have the wrong type, so malformed data can never lead to a revocation.
    """
    if not isinstance(raw, dict):
        raise JetBrainsSchemaError("License entry is not a JSON object")
    license_id = raw.get("licenseId")
    if not isinstance(license_id, str) or not license_id.strip():
        raise JetBrainsSchemaError("License entry has no valid 'licenseId'")
    product = raw.get("product") or {}
    if not isinstance(product, dict) or not product.get("code"):
        raise JetBrainsSchemaError(f"License {license_id} has no product code")
    team = raw.get("team") or {}
    if not isinstance(team, dict):
        raise JetBrainsSchemaError(f"License {license_id} has a malformed 'team'")

    assignee = raw.get("assignee")
    if assignee is None:
        a_type, a_email, a_name = AssigneeType.NONE, "", ""
    elif isinstance(assignee, dict):
        type_value = str(assignee.get("type") or "").upper()
        try:
            a_type = AssigneeType(type_value) if type_value else AssigneeType.UNKNOWN
        except ValueError:
            a_type = AssigneeType.UNKNOWN
        # Older payloads may omit "type" but carry an email: treat as USER only if an email exists.
        if a_type is AssigneeType.UNKNOWN and assignee.get("email"):
            a_type = AssigneeType.USER
        a_email = str(assignee.get("email") or "")
        a_name = str(assignee.get("name") or "")
    else:
        raise JetBrainsSchemaError(f"License {license_id} has a malformed 'assignee'")

    last_seen = raw.get("lastSeen") or {}
    if not isinstance(last_seen, dict):
        raise JetBrainsSchemaError(f"License {license_id} has a malformed 'lastSeen'")
    subscription = raw.get("subscription") or {}
    perpetual = raw.get("perpetual") or {}
    try:
        last_seen_date = parse_timestamp(last_seen.get("lastSeenDate"))
        last_assignment_date = parse_timestamp(last_seen.get("lastAssignmentDate"))
        valid_until = parse_timestamp(subscription.get("validUntilDate")) if isinstance(subscription, dict) else None
    except (TypeError, ValueError) as exc:
        raise JetBrainsSchemaError(f"License {license_id} has a malformed date: {exc}") from exc

    if raw.get("isTrial"):
        license_type = "TRIAL"
    elif isinstance(subscription, dict) and subscription:
        license_type = "SUBSCRIPTION"
    elif isinstance(perpetual, dict) and perpetual:
        license_type = "PERPETUAL"
    else:
        license_type = "UNKNOWN"

    team_id = team.get("id")
    return License(
        license_id=license_id.strip(),
        product_code=str(product.get("code")),
        product_name=str(product.get("name") or product.get("code")),
        team_id=int(team_id) if isinstance(team_id, int) else None,
        team_name=str(team.get("name") or ""),
        assignee_type=a_type,
        assignee_email=a_email,
        assignee_name=a_name,
        is_available_to_assign=raw.get("isAvailableToAssign"),
        is_suspended=raw.get("isSuspended"),
        is_trial=raw.get("isTrial"),
        last_seen_date=last_seen_date,
        last_assignment_date=last_assignment_date,
        is_offline_code_generated=last_seen.get("isOfflineCodeGenerated"),
        subscription_valid_until=valid_until,
        license_type=license_type,
    )


class JetBrainsClient:
    """Thin, defensive wrapper around the JetBrains Account API."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        customer_code: str,
        *,
        connect_timeout: float = 10.0,
        read_timeout: float = 60.0,
        max_retries: int = 4,
        backoff_base: float = 2.0,
        backoff_max: float = 60.0,
        ca_bundle: str | None = None,
        page_size: int = 100,
        max_pages: int = 1000,
        require_total_count: bool = True,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("JetBrains base URL must use HTTPS")
        if not api_token or not customer_code:
            raise ValueError("JetBrains API token and customer code are required")
        self.base_url = base_url.rstrip("/")
        self.timeout = (connect_timeout, read_timeout)
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.page_size = page_size
        self.max_pages = max_pages
        self.require_total_count = require_total_count
        self._sleep = sleep
        self.session = session or requests.Session()
        # Corporate CA bundles are supported; verification can never be disabled.
        self.session.verify = ca_bundle if ca_bundle else True
        # Proxies come from the standard HTTPS_PROXY / NO_PROXY environment variables.
        self.session.headers.update(
            {
                "X-Api-Key": api_token,
                "X-Customer-Code": customer_code,
                "Accept": "application/json",
                "User-Agent": "jetbrains-license-cleanup/1.0",
            }
        )

    # ------------------------------------------------------------------ HTTP
    def _backoff(self, attempt: int, retry_after: str | None = None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), self.backoff_max)
            except ValueError:
                pass
        delay = min(self.backoff_base * (2 ** attempt), self.backoff_max)
        return delay * (0.5 + random.random() / 2)  # jitter only, not security-related  # nosec B311

    def _get(self, path: str, params: dict[str, Any] | None = None, allow_404: bool = False) -> requests.Response | None:
        """GET with bounded retries for 429, 5xx, timeouts and connection errors."""
        url = f"{self.base_url}{path}"
        last_error = ""
        for attempt in range(self.max_retries + 1):
            try:
                # Never follow redirects: requests would re-send the X-Api-Key header to the new location.
                response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_error = f"network error: {type(exc).__name__}"
                log.warning("GET %s failed (%s), attempt %d/%d", path, last_error, attempt + 1, self.max_retries + 1)
                if attempt < self.max_retries:
                    self._sleep(self._backoff(attempt))
                continue
            if response.status_code in (401, 403):
                code, text = _safe_error_text(response)
                raise JetBrainsAuthError(
                    f"JetBrains API rejected the credentials or permissions for {path}: HTTP {response.status_code} {text}",
                    response.status_code, code,
                )
            if 300 <= response.status_code < 400:
                raise JetBrainsAPIError(
                    f"GET {path} returned an unexpected redirect (HTTP {response.status_code}); refusing to follow it "
                    "so the API token is not sent to another location", response.status_code,
                )
            if response.status_code == 404 and allow_404:
                return None
            if response.status_code == 429 or response.status_code >= 500:
                last_error = f"HTTP {response.status_code}"
                log.warning("GET %s returned %s, attempt %d/%d", path, last_error, attempt + 1, self.max_retries + 1)
                if attempt < self.max_retries:
                    self._sleep(self._backoff(attempt, response.headers.get("Retry-After")))
                continue
            if response.status_code >= 400:
                code, text = _safe_error_text(response)
                raise JetBrainsAPIError(f"GET {path} failed: HTTP {response.status_code} {text}", response.status_code, code)
            return response
        raise JetBrainsAPIError(f"GET {path} failed after {self.max_retries + 1} attempts ({last_error})")

    def _get_required(self, path: str, params: dict[str, Any] | None = None) -> requests.Response:
        response = self._get(path, params=params)
        if response is None:  # only possible with allow_404=True; kept explicit for safety
            raise JetBrainsAPIError(f"GET {path} returned no response", 404)
        return response

    @staticmethod
    def _json(response: requests.Response, path: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise JetBrainsSchemaError(f"{path} returned a non-JSON response") from exc

    # ------------------------------------------------------------ read APIs
    def get_token_info(self) -> dict[str, Any]:
        """Return the organization/team the token manages (``GET /token``)."""
        response = self._get_required("/token")
        body = self._json(response, "/token")
        if not isinstance(body, dict):
            raise JetBrainsSchemaError("/token returned an unexpected payload")
        return body

    def list_products(self) -> dict[str, str]:
        """Return the product dictionary as ``{code: name}`` (``GET /products``)."""
        response = self._get_required("/products")
        body = self._json(response, "/products")
        if not isinstance(body, list):
            raise JetBrainsSchemaError("/products did not return a list")
        products: dict[str, str] = {}
        for item in body:
            if isinstance(item, dict) and item.get("code"):
                products[str(item["code"])] = str(item.get("name") or item["code"])
        return products

    def _list_paged(self, path: str, assigned: bool) -> tuple[list[License], InventoryMeta]:
        meta = InventoryMeta()
        licenses: list[License] = []
        page = 1
        while True:
            if page > self.max_pages:
                raise InventoryIncompleteError(f"{path}: exceeded max_pages={self.max_pages}; refusing to continue")
            params = {"page": page, "perPage": self.page_size, "assigned": "true" if assigned else "false"}
            response = self._get_required(path, params=params)
            body = self._json(response, path)
            # The spec documents a JSON array; a PagedListResult {"data": [...]} is accepted defensively.
            items = body.get("data") if isinstance(body, dict) else body
            if not isinstance(items, list):
                raise JetBrainsSchemaError(f"{path} page {page} did not return a list of licenses")
            total_header = response.headers.get("X-Total-Count")
            if total_header is not None:
                try:
                    total = int(total_header)
                except ValueError as exc:
                    raise JetBrainsSchemaError(f"{path}: invalid X-Total-Count header") from exc
                if meta.reported_total is not None and total != meta.reported_total:
                    raise InventoryIncompleteError(f"{path}: total changed during pagination ({meta.reported_total} -> {total})")
                meta.reported_total = total
            licenses.extend(parse_license(item) for item in items)
            meta.pages_fetched += 1
            if not items or len(items) < self.page_size:
                break
            if meta.reported_total is not None and len(licenses) >= meta.reported_total:
                break
            page += 1
        meta.collected = len(licenses)
        if meta.reported_total is None:
            if self.require_total_count:
                raise InventoryIncompleteError(f"{path}: X-Total-Count header missing; completeness cannot be verified")
            meta.complete = True
        else:
            meta.complete = meta.collected == meta.reported_total
            if not meta.complete:
                raise InventoryIncompleteError(
                    f"{path}: collected {meta.collected} licenses but API reported {meta.reported_total}"
                )
        return licenses, meta

    def list_licenses(self, team_ids: list[int] | None = None) -> tuple[list[License], list[InventoryMeta]]:
        """Return all licenses (assigned and unassigned) with completeness metadata.

        The API's ``assigned`` filter defaults to ``false`` (available licenses
        only), so both ``assigned=true`` and ``assigned=false`` are fetched
        explicitly. Duplicate license IDs abort the inventory.
        """
        paths = [f"/customer/teams/{int(t)}/licenses" for t in team_ids] if team_ids else ["/customer/licenses"]
        all_licenses: list[License] = []
        metas: list[InventoryMeta] = []
        for path in paths:
            for assigned in (True, False):
                items, meta = self._list_paged(path, assigned)
                all_licenses.extend(items)
                metas.append(meta)
        seen: set[str] = set()
        for lic in all_licenses:
            if lic.license_id in seen:
                raise InventoryIncompleteError(f"Duplicate license id {lic.license_id} in inventory; results are inconsistent")
            seen.add(lic.license_id)
        return all_licenses, metas

    def get_license(self, license_id: str) -> License | None:
        """Return current details of one license, or ``None`` if it no longer exists."""
        response = self._get(f"/customer/licenses/{requests.utils.quote(license_id, safe='')}", allow_404=True)
        if response is None:
            return None
        return parse_license(self._json(response, "/customer/licenses/{id}"))

    # ----------------------------------------------------------- write API
    def revoke_license(self, license_id: str) -> RevokeResponse:
        """Revoke exactly one license by ID.

        Only ``licenseId`` is sent; never ``email`` (which would revoke every
        license of the user). This call is **not** retried on timeouts or 5xx
        because the outcome is unknown; the caller must re-read the license
        state instead. HTTP 429 means the request was rejected before
        processing and is retried with backoff.
        """
        url = f"{self.base_url}/customer/licenses/revoke"
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.post(url, params={"licenseId": license_id}, timeout=self.timeout,
                                             allow_redirects=False)
            except (requests.ConnectionError, requests.Timeout) as exc:
                return RevokeResponse(RevokeOutcome.UNCERTAIN, [], 0, message=f"network error: {type(exc).__name__}")
            if response.status_code == 429 and attempt < self.max_retries:
                self._sleep(self._backoff(attempt, response.headers.get("Retry-After")))
                continue
            if response.status_code in (401, 403):
                code, text = _safe_error_text(response)
                raise JetBrainsAuthError(f"Revoke rejected: HTTP {response.status_code} {text}", response.status_code, code)
            if 300 <= response.status_code < 400:
                # Not followed (would leak the token); the state is re-read by the caller.
                return RevokeResponse(RevokeOutcome.UNCERTAIN, [], response.status_code,
                                      message=f"unexpected redirect HTTP {response.status_code} (not followed)")
            if response.status_code >= 500:
                return RevokeResponse(RevokeOutcome.UNCERTAIN, [], response.status_code, message=f"HTTP {response.status_code}")
            if response.status_code >= 400:
                code, text = _safe_error_text(response)
                return RevokeResponse(RevokeOutcome.REJECTED, [], response.status_code, code, text)
            try:
                body = response.json()
            except ValueError:
                return RevokeResponse(RevokeOutcome.UNCERTAIN, [], response.status_code, message="non-JSON success response")
            ids = body.get("licenseIds") if isinstance(body, dict) else None
            if not isinstance(ids, list):
                return RevokeResponse(RevokeOutcome.UNCERTAIN, [], response.status_code, message="unexpected success payload")
            ids = [str(i) for i in ids]
            if license_id in ids:
                return RevokeResponse(RevokeOutcome.REVOKED, ids, response.status_code)
            return RevokeResponse(RevokeOutcome.UNCERTAIN, ids, response.status_code, message="license id not in response")
        return RevokeResponse(RevokeOutcome.REJECTED, [], 429, message="rate limited; not revoked")
