"""Pre-revocation safety gates.

Every check returns a list of human-readable violations. Any violation
blocks *all* revocations for the run; reports are still produced.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .config_manager import AppConfig, SafetyConfig
from .jetbrains_client import InventoryMeta
from .models import Action, ADLookupResult, ADStatus, Decision, License


@dataclass
class SafetyReport:
    ok: bool
    violations: list[str] = field(default_factory=list)
    proposed_revocations: int = 0
    assigned_licenses: int = 0
    ad_lookup_failures: int = 0
    ad_lookups: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "violations": self.violations,
            "proposed_revocations": self.proposed_revocations,
            "assigned_licenses": self.assigned_licenses,
            "ad_lookup_failures": self.ad_lookup_failures,
            "ad_lookups": self.ad_lookups,
        }


class ProductionNotAllowedError(Exception):
    """Raised when a production run is requested without explicit approval."""


def resolve_dry_run(config: AppConfig, trigger: str, requested_dry_run: bool) -> bool:
    """Decide whether this execution may perform real revocations.

    * ``execution.production_enabled`` must be ``true`` in the reviewed config
      for *any* run to revoke licenses.
    * Scheduled (timer) runs ignore build parameters and follow
      ``execution.scheduled_mode`` only.
    * Manual runs revoke only when the operator explicitly sets DRY_RUN=false.
    """
    if trigger not in ("scheduled", "manual"):
        raise ValueError("trigger must be 'scheduled' or 'manual'")
    if trigger == "scheduled":
        wants_production = config.execution.scheduled_mode == "production"
    else:
        wants_production = not requested_dry_run
    if not wants_production:
        return True
    if not config.execution.production_enabled:
        raise ProductionNotAllowedError(
            "Production mode requested but execution.production_enabled is false in the approved configuration"
        )
    return False


def check_inventory(licenses: list[License], metas: list[InventoryMeta], expected_min: int) -> list[str]:
    """Verify the inventory is complete and plausible."""
    violations: list[str] = []
    if not metas or not all(m.complete for m in metas):
        violations.append("License inventory pagination did not complete")
    if len(licenses) < expected_min:
        violations.append(f"Only {len(licenses)} licenses found; expected at least {expected_min} (inventory looks incomplete)")
    return violations


def check_ad_health(ad_results: dict[str, ADLookupResult], max_failure_percent: float) -> tuple[list[str], int, int]:
    """Abort when too many directory lookups failed."""
    total = len(ad_results)
    failures = sum(1 for r in ad_results.values() if r.status is ADStatus.ERROR)
    violations: list[str] = []
    if total and failures / total * 100 > max_failure_percent:
        violations.append(
            f"AD lookup failure rate {failures}/{total} ({failures / total:.1%}) exceeds {max_failure_percent}%"
        )
    return violations, failures, total


def check_thresholds(decisions: list[Decision], safety: SafetyConfig) -> tuple[list[str], int, int]:
    """Mass-revocation protection based on count and percentage of assigned licenses."""
    proposed = sum(1 for d in decisions if d.action is Action.REVOKE)
    assigned = sum(1 for d in decisions if d.license.is_assigned)
    violations: list[str] = []
    if proposed > safety.max_revocations:
        violations.append(f"{proposed} proposed revocations exceed MAX_REVOCATIONS={safety.max_revocations}")
    if assigned:
        allowed = math.floor(assigned * safety.max_revocation_percent / 100)
        if proposed > allowed:
            violations.append(
                f"{proposed} proposed revocations exceed {safety.max_revocation_percent}% of {assigned} assigned licenses (max {allowed})"
            )
    elif proposed:
        violations.append("Revocations proposed but no assigned licenses counted (inconsistent data)")
    return violations, proposed, assigned


def run_safety_checks(
    licenses: list[License],
    metas: list[InventoryMeta],
    ad_results: dict[str, ADLookupResult],
    decisions: list[Decision],
    config: AppConfig,
) -> SafetyReport:
    """Run every gate and aggregate the result."""
    violations = check_inventory(licenses, metas, config.jetbrains.expected_min_licenses)
    ad_violations, failures, lookups = check_ad_health(ad_results, config.safety.max_ad_lookup_failure_percent)
    threshold_violations, proposed, assigned = check_thresholds(decisions, config.safety)
    violations += ad_violations + threshold_violations
    return SafetyReport(
        ok=not violations,
        violations=violations,
        proposed_revocations=proposed,
        assigned_licenses=assigned,
        ad_lookup_failures=failures,
        ad_lookups=lookups,
    )
