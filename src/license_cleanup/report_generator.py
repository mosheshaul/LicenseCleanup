"""CSV audit report and JSON execution summary.

Reports contain only what an audit needs: license, product, email and AD
account identifiers. No credentials, tokens or AD attributes beyond the
listed columns are written. Every CSV cell is protected against spreadsheet
formula injection.
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Action, ADStatus, Decision, Result, Verification, format_timestamp

CSV_COLUMNS = [
    "Timestamp", "ExecutionID", "JetBrainsTeam", "ProductName", "LicenseID", "LicenseType",
    "LicenseAssignedDate", "JetBrainsUsername", "EmailAddress", "ADSamAccountName", "ADUserPrincipalName",
    "ADAccountStatus", "ADLookupStatus", "LastProductUsage", "UsageDataSource", "DaysSinceLastUsage",
    "InactivityThreshold", "ExclusionStatus", "RevocationReason", "ProposedAction", "ActualAction", "DryRun",
    "Result", "VerificationStatus", "ErrorMessage",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "|", "%")


def sanitize_cell(value: Any) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    stripped = text.lstrip(" \t")
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        # Leave plain negative numbers alone; anything else gets a leading quote.
        try:
            float(text)
            return text
        except ValueError:
            return "'" + text
    return text


def _ad_lookup_status(decision: Decision) -> str:
    ad = decision.ad
    if ad.status in (ADStatus.ENABLED, ADStatus.DISABLED):
        return f"FOUND_{'STRONG' if ad.strong_match else 'WEAK'}_{ad.matched_attribute}"
    return ad.status.value


def _ad_account_status(decision: Decision) -> str:
    status = decision.ad.status
    return status.value if status in (ADStatus.ENABLED, ADStatus.DISABLED) else "UNKNOWN"


def decision_to_row(decision: Decision, execution_id: str, timestamp: datetime, dry_run: bool) -> dict[str, str]:
    lic = decision.license
    return {
        "Timestamp": format_timestamp(timestamp),
        "ExecutionID": execution_id,
        "JetBrainsTeam": lic.team_name,
        "ProductName": lic.product_name,
        "LicenseID": lic.license_id,
        "LicenseType": lic.license_type,
        "LicenseAssignedDate": format_timestamp(lic.last_assignment_date),
        "JetBrainsUsername": lic.assignee_name,
        "EmailAddress": lic.assignee_email,
        "ADSamAccountName": decision.ad.sam_account_name,
        "ADUserPrincipalName": decision.ad.user_principal_name,
        "ADAccountStatus": _ad_account_status(decision) if lic.assignee_email else "",
        "ADLookupStatus": _ad_lookup_status(decision) if lic.assignee_email else "",
        "LastProductUsage": format_timestamp(lic.last_seen_date),
        "UsageDataSource": decision.usage_data_source,
        "DaysSinceLastUsage": "" if decision.days_since_last_usage is None else str(decision.days_since_last_usage),
        "InactivityThreshold": format_timestamp(decision.threshold),
        "ExclusionStatus": decision.exclusion_status,
        "RevocationReason": decision.reason.value,
        "ProposedAction": decision.action.value,
        "ActualAction": decision.actual_action,
        "DryRun": str(dry_run).lower(),
        "Result": decision.result.value,
        "VerificationStatus": decision.verification.value,
        "ErrorMessage": decision.error_message or ("" if decision.action is Action.REVOKE else decision.explanation),
    }


def write_csv(path: Path, decisions: list[Decision], execution_id: str, timestamp: datetime, dry_run: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Reports contain personal data: create them readable by the owner only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for decision in decisions:
            row = decision_to_row(decision, execution_id, timestamp, dry_run)
            writer.writerow({k: sanitize_cell(v) for k, v in row.items()})
    return path


@dataclass
class Summary:
    execution_id: str
    started_at: datetime
    finished_at: datetime
    dry_run: bool
    trigger: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)


def build_summary(
    decisions: list[Decision],
    *,
    execution_id: str,
    started_at: datetime,
    finished_at: datetime,
    dry_run: bool,
    trigger: str,
    products_catalog_size: int | None,
    safety: dict[str, Any] | None,
    status: str,
    pricing: dict[str, float] | None = None,
    pricing_source: str = "",
    currency: str = "USD",
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build the JSON execution summary (aggregates only, no personal data)."""
    assigned = [d for d in decisions if d.license.is_assigned]
    users: dict[str, ADStatus] = {}
    for d in assigned:
        if d.license.assignee_email:
            users[d.license.assignee_email.casefold()] = d.ad.status
    revoked = [d for d in decisions if d.result is Result.REVOKED]
    eligible = [d for d in decisions if d.action is Action.REVOKE]

    by_product: dict[str, Counter[str]] = defaultdict(Counter)
    for d in revoked if not dry_run else eligible:
        by_product[d.license.product_name][d.reason.value] += 1

    savings: dict[str, Any] = {
        "reclaimed_license_capacity": len(revoked) if not dry_run else 0,
        "potential_reclaimable_capacity": len(eligible),
        "subscription_cost_reduction": None,
        "note": (
            "Revoked licenses return to the organization's pool; the subscription bill only decreases "
            "if seats are reduced at renewal. The JetBrains Account API exposes no pricing data."
        ),
    }
    if pricing:
        reclaimable_value = 0.0
        unpriced = Counter[str]()
        for d in (eligible if dry_run else revoked):
            price = pricing.get(d.license.product_code)
            if price is None:
                unpriced[d.license.product_code] += 1
            else:
                reclaimable_value += float(price)
        savings.update({
            "estimated_value_of_reclaimed_capacity": round(reclaimable_value, 2),
            "currency": currency,
            "pricing_source": pricing_source or "administrator-provided configuration",
            "unpriced_products": dict(unpriced),
        })

    counts = Counter(d.action for d in decisions)
    product_codes = {d.license.product_code for d in decisions}
    return {
        "execution_id": execution_id,
        "trigger": trigger,
        "mode": "DRY_RUN" if dry_run else "PRODUCTION",
        "started_at": format_timestamp(started_at),
        "finished_at": format_timestamp(finished_at),
        "execution_duration_seconds": round((finished_at - started_at).total_seconds(), 1),
        "overall_status": status,
        "totals": {
            "products_discovered": len(product_codes),
            "products_in_catalog": products_catalog_size,
            "licenses_discovered": len(decisions),
            "assigned_licenses": len(assigned),
            "unassigned_licenses": len(decisions) - len(assigned),
            "unique_licensed_users": len(users),
            "enabled_users": sum(1 for s in users.values() if s is ADStatus.ENABLED),
            "disabled_users": sum(1 for s in users.values() if s is ADStatus.DISABLED),
            "inactive_license_assignments": sum(1 for d in eligible if d.reason.value == "PRODUCT_INACTIVE"),
            "excluded_licenses": sum(1 for d in decisions if d.exclusion_status != "NOT_EXCLUDED"),
            "manual_review": counts.get(Action.MANUAL_REVIEW, 0),
            "not_revoked_due_to_lookup_failure": counts.get(Action.DO_NOT_REVOKE, 0),
            "eligible_for_revocation": len(eligible),
            "successfully_revoked": len(revoked),
            "revocations_verified": sum(1 for d in revoked if d.verification is Verification.VERIFIED),
            "failed_revocations": sum(1 for d in decisions if d.result in (Result.FAILED, Result.UNCERTAIN)),
            "skipped_after_revalidation": sum(1 for d in decisions if d.result is Result.SKIPPED_REVALIDATION),
            "aborted_revocations": sum(1 for d in decisions if d.result is Result.ABORTED),
            "retained_licenses": counts.get(Action.KEEP, 0),
        },
        "revoked_by_product_and_reason" if not dry_run else "would_revoke_by_product_and_reason":
            {p: dict(c) for p, c in sorted(by_product.items())},
        "safety": safety or {},
        "cost": savings,
        "errors": errors or [],
    }


def write_json(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
    return path
