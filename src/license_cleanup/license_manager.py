"""License evaluation (business rules) and the guarded revocation workflow.

Usage data
----------
The only official per-assignment usage signal in the JetBrains Account API
is ``lastSeen.lastSeenDate`` on each license. It is recorded **per license**
(i.e. per product assignment), not per user. Consequently:

* Each independently assigned product license is evaluated on its own.
* A bundle such as the All Products Pack is a single license whose
  ``lastSeenDate`` reflects use of *any* product it covers, so recent use of
  any covered IDE keeps the bundle.

The following are never used as a substitute for product usage:
``lastAssignmentDate``, JetBrains website logins, or account creation dates.
When usage cannot be attributed reliably to the current assignee, the
license goes to manual review.
"""

from __future__ import annotations

import calendar
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .ad_client import ADAuthError, ADClient, ADConnectionError, ADSearchError, normalize_email
from .config_manager import Exclusions, PolicyConfig, SafetyConfig
from .jetbrains_client import (
    RECENTLY_ASSIGNED_ERROR,
    JetBrainsAPIError,
    JetBrainsClient,
    RevokeOutcome,
)
from .models import (
    Action,
    ADLookupResult,
    ADStatus,
    AssigneeType,
    Decision,
    License,
    Result,
    RevocationReason,
    Verification,
)

log = logging.getLogger(__name__)

USAGE_SOURCE = "JetBrainsAccountAPI:lastSeen.lastSeenDate"


def subtract_calendar_months(moment: datetime, months: int) -> datetime:
    """Subtract calendar months, clamping the day (e.g. 31 Aug - 6 months = 28/29 Feb)."""
    if moment.tzinfo is None:
        raise ValueError("moment must be timezone-aware")
    total = moment.year * 12 + (moment.month - 1) - months
    year, month = divmod(total, 12)
    month += 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def inactivity_threshold(now: datetime, months: int) -> datetime:
    """Return the cut-off: usage strictly before this instant counts as inactive."""
    return subtract_calendar_months(now.astimezone(timezone.utc), months)


def lookup_ad_users(licenses: Iterable[License], ad: ADClient) -> dict[str, ADLookupResult]:
    """Look up every unique assignee email in AD.

    Per-user search errors are recorded as ``LOOKUP_ERROR``. Losing the
    connection or failing authentication raises, so the run aborts.
    """
    results: dict[str, ADLookupResult] = {}
    for lic in licenses:
        if lic.assignee_type is not AssigneeType.USER:
            continue
        email = normalize_email(lic.assignee_email)
        if email in results:
            continue
        try:
            results[email] = ad.lookup(email)
        except (ADConnectionError, ADAuthError):
            raise
        except ADSearchError as exc:
            results[email] = ADLookupResult(email=email, status=ADStatus.ERROR, message=str(exc))
    return results


def _days_between(later: datetime, earlier: datetime) -> int:
    return (later - earlier).days


def evaluate_license(
    lic: License,
    ad_result: ADLookupResult | None,
    exclusions: Exclusions,
    policy: PolicyConfig,
    now: datetime,
) -> Decision:
    """Apply the business rules to a single license and return a :class:`Decision`."""
    threshold = inactivity_threshold(now, policy.inactivity_months)
    ad = ad_result or ADLookupResult(email=normalize_email(lic.assignee_email), status=ADStatus.NOT_CHECKED)
    days_since = _days_between(now, lic.last_seen_date) if lic.last_seen_date else None
    source = USAGE_SOURCE if lic.last_seen_date else "UNAVAILABLE"

    def decide(action: Action, explanation: str, reason: RevocationReason = RevocationReason.NONE,
               exclusion: str = "NOT_EXCLUDED") -> Decision:
        return Decision(license=lic, ad=ad, action=action, reason=reason, explanation=explanation,
                        exclusion_status=exclusion, threshold=threshold, days_since_last_usage=days_since,
                        usage_data_source=source)

    # Not assigned to anyone: nothing to reclaim.
    if lic.assignee_type is AssigneeType.NONE:
        return decide(Action.SKIP, "License is unassigned")
    # Assigned to a license server / key: not a person, out of scope.
    if lic.assignee_type is not AssigneeType.USER:
        return decide(Action.SKIP, f"Assignee type {lic.assignee_type.value} is not a user")
    if not lic.assignee_email:
        return decide(Action.MANUAL_REVIEW, "Assigned license has no assignee email")

    # 1. Exclusions
    exclusion = exclusions.match(lic.assignee_email, lic.license_id, lic.product_code, lic.team_id, lic.team_name)
    if exclusion:
        return decide(Action.KEEP, "License or user is excluded from cleanup", exclusion=exclusion)

    # 2. Directory state
    if ad.status in (ADStatus.ERROR, ADStatus.NOT_CHECKED):
        return decide(Action.DO_NOT_REVOKE, f"Active Directory lookup failed: {ad.message or ad.status.value}")
    if ad.status is ADStatus.MULTIPLE:
        return decide(Action.MANUAL_REVIEW, f"Multiple matching AD accounts ({ad.message})")
    if ad.status is ADStatus.NOT_FOUND:
        return decide(Action.MANUAL_REVIEW, "User not found in Active Directory (not treated as disabled)")
    if ad.status is ADStatus.EXTERNAL:
        return decide(Action.MANUAL_REVIEW, "External/contractor user without an AD account")
    if not ad.strong_match:
        return decide(Action.MANUAL_REVIEW, f"Identity not verified unambiguously: {ad.message}")

    if ad.status is ADStatus.DISABLED:
        if not policy.revoke_disabled_users:
            return decide(Action.KEEP, "AD account disabled, but disabled-user revocation is turned off")
        return _apply_assignment_age_guard(
            decide(Action.REVOKE, "Active Directory account is disabled", RevocationReason.AD_DISABLED), policy, now)

    # 3. Enabled user: per-license usage
    if lic.is_offline_code_generated:
        return decide(Action.MANUAL_REVIEW,
                      "Offline activation code generated: IDE does not report usage, last-seen date is unreliable")
    if lic.last_seen_date is None:
        return decide(Action.MANUAL_REVIEW, "Product usage date unavailable (missing usage is not proof of non-use)")
    if lic.last_assignment_date is None:
        return decide(Action.MANUAL_REVIEW,
                      "Assignment date unavailable, so the last-seen date cannot be attributed to the current assignee")
    if lic.last_seen_date < lic.last_assignment_date:
        return decide(Action.MANUAL_REVIEW,
                      "Last-seen date predates the current assignment, so it may belong to a previous assignee")
    if lic.last_seen_date > now + timedelta(days=1):
        return decide(Action.MANUAL_REVIEW, "Last-seen date is in the future; data looks invalid")
    if lic.last_seen_date < threshold:
        if not policy.revoke_inactive_users:
            return decide(Action.KEEP, "Inactive, but inactivity-based revocation is turned off")
        return _apply_assignment_age_guard(
            decide(Action.REVOKE,
                   f"Product last used {days_since} days ago, before the {policy.inactivity_months}-month threshold",
                   RevocationReason.INACTIVE),
            policy, now)
    return decide(Action.KEEP, f"Product used within the last {policy.inactivity_months} months")


def _apply_assignment_age_guard(decision: Decision, policy: PolicyConfig, now: datetime) -> Decision:
    """JetBrains only allows revoking licenses assigned at least 30 days ago."""
    assigned = decision.license.last_assignment_date
    if assigned and now - assigned < timedelta(days=policy.min_assignment_age_days):
        decision.action = Action.MANUAL_REVIEW
        decision.explanation += (
            f"; deferred: assigned less than {policy.min_assignment_age_days} days ago (JetBrains revocation rule)"
        )
    return decision


def evaluate_all(
    licenses: list[License],
    ad_results: dict[str, ADLookupResult],
    exclusions: Exclusions,
    policy: PolicyConfig,
    now: datetime,
) -> list[Decision]:
    """Evaluate every license independently."""
    return [
        evaluate_license(lic, ad_results.get(normalize_email(lic.assignee_email)), exclusions, policy, now)
        for lic in licenses
    ]


# --------------------------------------------------------------------------- revocation


@dataclass
class RevocationRun:
    """Mutable bookkeeping for one revocation pass."""

    attempted: set[str] = field(default_factory=set)
    consecutive_failures: int = 0
    aborted: bool = False
    abort_reason: str = ""


def _revalidate(
    decision: Decision,
    client: JetBrainsClient,
    ad: ADClient | None,
    exclusions: Exclusions,
    policy: PolicyConfig,
    now: datetime,
) -> tuple[bool, str]:
    """Re-read the license (and AD state) immediately before revoking.

    Returns ``(ok, message)``. ``ok`` is False when the license changed or the
    decision no longer holds; the license is then left untouched.
    """
    original = decision.license
    current = client.get_license(original.license_id)
    if current is None:
        return False, "License no longer exists"
    if current.assignee_type is AssigneeType.NONE:
        return False, "License is already unassigned (already revoked)"
    if normalize_email(current.assignee_email) != normalize_email(original.assignee_email):
        return False, "License was reassigned to a different user since inventory"
    ad_result = decision.ad
    if decision.reason is RevocationReason.AD_DISABLED:
        if ad is None:
            return False, "AD client unavailable for revalidation"
        fresh = ad.lookup(current.assignee_email, use_cache=False)
        ad_result = fresh
    new_decision = evaluate_license(current, ad_result, exclusions, policy, now)
    if new_decision.action is not Action.REVOKE or new_decision.reason is not decision.reason:
        return False, f"Decision changed on revalidation: {new_decision.action.value} ({new_decision.explanation})"
    return True, ""


def verify_revocation(client: JetBrainsClient, license_id: str, original_email: str) -> Verification:
    """Confirm via the API that the license is no longer assigned to the original user."""
    try:
        current = client.get_license(license_id)
    except JetBrainsAPIError:
        return Verification.NOT_VERIFIED
    if current is None or current.assignee_type is AssigneeType.NONE:
        return Verification.VERIFIED
    if normalize_email(current.assignee_email) != normalize_email(original_email):
        return Verification.VERIFIED  # reassigned to someone else after revocation
    return Verification.NOT_VERIFIED


def execute_revocations(
    decisions: list[Decision],
    client: JetBrainsClient | None,
    ad: ADClient | None,
    exclusions: Exclusions,
    policy: PolicyConfig,
    safety: SafetyConfig,
    *,
    dry_run: bool,
    now: datetime,
) -> RevocationRun:
    """Revoke every decision marked REVOKE (or simulate it in dry-run mode).

    Guarantees:
    * Dry-run never calls a write endpoint (the client is not even touched).
    * Each license id is attempted at most once per run.
    * Each candidate is revalidated right before revocation.
    * Uncertain outcomes are resolved by reading the license state, never by retrying.
    * Too many consecutive failures abort the remaining revocations.
    """
    run = RevocationRun()
    for decision in decisions:
        if decision.action is not Action.REVOKE:
            continue
        lic_id = decision.license.license_id
        if dry_run:
            decision.result = Result.DRY_RUN
            decision.actual_action = "NONE (dry run)"
            decision.verification = Verification.NOT_APPLICABLE
            continue
        if client is None:
            raise RuntimeError("Production revocation requires a JetBrains client")
        if run.aborted:
            decision.result = Result.ABORTED
            decision.error_message = run.abort_reason
            continue
        if lic_id in run.attempted:
            decision.result = Result.SKIPPED_REVALIDATION
            decision.error_message = "Duplicate revocation attempt prevented"
            continue
        run.attempted.add(lic_id)

        try:
            ok, message = _revalidate(decision, client, ad, exclusions, policy, now)
        except (JetBrainsAPIError, ADConnectionError, ADAuthError, ADSearchError) as exc:
            ok, message = False, f"Revalidation failed: {exc}"
        if not ok:
            decision.result = Result.SKIPPED_REVALIDATION
            decision.actual_action = "NONE"
            decision.error_message = message
            log.info("License %s not revoked: %s", lic_id, message)
            continue

        response = client.revoke_license(lic_id)
        extra_ids = [i for i in response.revoked_ids if i != lic_id]
        if extra_ids:
            # Should never happen when revoking by licenseId; stop immediately if it does.
            run.aborted = True
            run.abort_reason = f"API reported revoking unexpected license ids {extra_ids}; aborting"
            log.error(run.abort_reason)

        if response.outcome is RevokeOutcome.REVOKED:
            decision.result = Result.REVOKED
            decision.actual_action = "REVOKED"
            decision.verification = verify_revocation(client, lic_id, decision.license.assignee_email)
            if decision.verification is not Verification.VERIFIED:
                decision.error_message = "Revocation reported by API but not confirmed on re-read"
            run.consecutive_failures = 0
        elif response.outcome is RevokeOutcome.UNCERTAIN:
            # Never retry blindly: inspect the current license state.
            verification = verify_revocation(client, lic_id, decision.license.assignee_email)
            decision.verification = verification
            if verification is Verification.VERIFIED:
                decision.result = Result.REVOKED
                decision.actual_action = "REVOKED"
                decision.error_message = f"Uncertain API response ({response.message}); state confirms revocation"
                run.consecutive_failures = 0
            else:
                decision.result = Result.UNCERTAIN
                decision.actual_action = "UNKNOWN"
                decision.error_message = f"Uncertain API response ({response.message}); license still assigned or unreadable"
                run.consecutive_failures += 1
        else:
            decision.result = Result.FAILED
            decision.actual_action = "NONE"
            decision.verification = Verification.NOT_APPLICABLE
            if response.error_code == RECENTLY_ASSIGNED_ERROR:
                decision.error_message = "JetBrains refused: license assigned less than 30 days ago"
            else:
                decision.error_message = f"Revocation rejected: HTTP {response.status} {response.error_code} {response.message}".strip()
            run.consecutive_failures += 1

        if run.consecutive_failures >= safety.max_consecutive_revocation_failures and not run.aborted:
            run.aborted = True
            run.abort_reason = f"Aborted after {run.consecutive_failures} consecutive revocation failures"
            log.error(run.abort_reason)
    return run
