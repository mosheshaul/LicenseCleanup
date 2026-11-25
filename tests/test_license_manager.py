"""Business rules and revocation workflow tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from conftest import NOW, FakeLDAPConnection, ad_user, make_license
from license_cleanup.ad_client import ADClient
from license_cleanup.config_manager import Exclusions, PolicyConfig, SafetyConfig
from license_cleanup.jetbrains_client import RevokeOutcome, RevokeResponse
from license_cleanup.license_manager import (
    evaluate_all,
    evaluate_license,
    execute_revocations,
    inactivity_threshold,
    subtract_calendar_months,
)
from license_cleanup.models import Action, ADLookupResult, ADStatus, AssigneeType, License, Result, RevocationReason, Verification

UTC = timezone.utc
ENABLED = ADLookupResult("alice@example.com", ADStatus.ENABLED, "alice", "alice@corp", "mail", True)
DISABLED = ADLookupResult("alice@example.com", ADStatus.DISABLED, "alice", "alice@corp", "mail", True)
NO_EXCL = Exclusions()


class FakeJetBrains:
    """Records every call; licenses are held in memory."""

    def __init__(self, licenses: list[License], revoke_outcome: RevokeOutcome = RevokeOutcome.REVOKED,
                 apply_revoke: bool = True) -> None:
        self.licenses = {lic.license_id: lic for lic in licenses}
        self.revoke_calls: list[str] = []
        self.revoke_outcome = revoke_outcome
        self.apply_revoke = apply_revoke

    def get_license(self, license_id: str) -> License | None:
        return self.licenses.get(license_id)

    def revoke_license(self, license_id: str) -> RevokeResponse:
        self.revoke_calls.append(license_id)
        if self.apply_revoke and license_id in self.licenses:
            lic = self.licenses[license_id]
            self.licenses[license_id] = replace(lic, assignee_type=AssigneeType.NONE, assignee_email="")
        if self.revoke_outcome is RevokeOutcome.REVOKED:
            return RevokeResponse(RevokeOutcome.REVOKED, [license_id], 200)
        if self.revoke_outcome is RevokeOutcome.REJECTED:
            return RevokeResponse(RevokeOutcome.REJECTED, [], 400, "SOME_ERROR", "rejected")
        return RevokeResponse(RevokeOutcome.UNCERTAIN, [], 504, message="HTTP 504")


def ad_for(ad_config, users) -> ADClient:
    client = ADClient(ad_config, "svc@corp.example.test", "fake", connection_factory=lambda *_: FakeLDAPConnection(users))
    client.connect()
    return client


# ------------------------------------------------------------ date math
def test_six_calendar_months_not_days() -> None:
    assert subtract_calendar_months(datetime(2026, 8, 31, tzinfo=UTC), 6) == datetime(2026, 2, 28, tzinfo=UTC)
    assert subtract_calendar_months(datetime(2024, 8, 31, tzinfo=UTC), 6) == datetime(2024, 2, 29, tzinfo=UTC)
    assert subtract_calendar_months(datetime(2026, 3, 15, tzinfo=UTC), 6) == datetime(2025, 9, 15, tzinfo=UTC)
    with pytest.raises(ValueError):
        subtract_calendar_months(datetime(2026, 3, 15), 6)


# ------------------------------------------------------------ rules
def test_disabled_employee_is_revoked(policy) -> None:
    d = evaluate_license(make_license(), DISABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.REVOKE and d.reason is RevocationReason.AD_DISABLED


def test_enabled_recent_usage_is_kept(policy) -> None:
    d = evaluate_license(make_license(last_seen=datetime(2026, 9, 1, tzinfo=UTC)), ENABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.KEEP


def test_enabled_inactive_more_than_six_months_is_revoked(policy) -> None:
    d = evaluate_license(make_license(last_seen=datetime(2026, 3, 1, tzinfo=UTC)), ENABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.REVOKE and d.reason is RevocationReason.INACTIVE


def test_inactive_exactly_six_months_is_kept(policy) -> None:
    threshold = inactivity_threshold(NOW, 6)
    assert threshold == datetime(2026, 5, 1, 2, 30, tzinfo=UTC)
    d = evaluate_license(make_license(last_seen=threshold), ENABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.KEEP
    just_before = threshold.replace(second=0, minute=29)
    assert evaluate_license(make_license(last_seen=just_before), ENABLED, NO_EXCL, policy, NOW).action is Action.REVOKE


def test_user_not_found_goes_to_manual_review(policy) -> None:
    nf = ADLookupResult("alice@example.com", ADStatus.NOT_FOUND)
    assert evaluate_license(make_license(), nf, NO_EXCL, policy, NOW).action is Action.MANUAL_REVIEW


def test_multiple_ad_matches_manual_review(policy) -> None:
    multi = ADLookupResult("alice@example.com", ADStatus.MULTIPLE, strong_match=True)
    assert evaluate_license(make_license(), multi, NO_EXCL, policy, NOW).action is Action.MANUAL_REVIEW


def test_weak_identity_match_manual_review_even_if_disabled(policy) -> None:
    weak = ADLookupResult("alice@example.com", ADStatus.DISABLED, "alice", "", "sAMAccountName", False)
    assert evaluate_license(make_license(), weak, NO_EXCL, policy, NOW).action is Action.MANUAL_REVIEW


def test_ad_lookup_failure_does_not_revoke(policy) -> None:
    err = ADLookupResult("alice@example.com", ADStatus.ERROR, message="timeout")
    d = evaluate_license(make_license(last_seen=datetime(2025, 1, 1, tzinfo=UTC)), err, NO_EXCL, policy, NOW)
    assert d.action is Action.DO_NOT_REVOKE


def test_multiple_product_licenses_evaluated_independently(policy) -> None:
    idea = make_license("L1", product_code="II", last_seen=datetime(2026, 10, 20, tzinfo=UTC))
    pycharm = make_license("L2", product_code="PC", product_name="PyCharm Professional",
                           last_seen=datetime(2026, 3, 20, tzinfo=UTC))
    decisions = evaluate_all([idea, pycharm], {"alice@example.com": ENABLED}, NO_EXCL, policy, NOW)
    assert [d.action for d in decisions] == [Action.KEEP, Action.REVOKE]


def test_disabled_user_loses_all_licenses(policy) -> None:
    lics = [make_license("L1"), make_license("L2", product_code="PC"), make_license("L3", product_code="WS")]
    decisions = evaluate_all(lics, {"alice@example.com": DISABLED}, NO_EXCL, policy, NOW)
    assert all(d.action is Action.REVOKE for d in decisions)


def test_all_products_pack_kept_when_any_covered_product_recently_used(policy) -> None:
    # A single All Products Pack license: its lastSeenDate covers every IDE in the bundle.
    pack = make_license("L1", product_code="ALL", product_name="All Products Pack",
                        last_seen=datetime(2026, 10, 30, tzinfo=UTC))
    assert evaluate_license(pack, ENABLED, NO_EXCL, policy, NOW).action is Action.KEEP
    stale = replace(pack, last_seen_date=datetime(2026, 1, 1, tzinfo=UTC))
    assert evaluate_license(stale, ENABLED, NO_EXCL, policy, NOW).action is Action.REVOKE


def test_excluded_user_is_kept_even_if_disabled(policy) -> None:
    excl = Exclusions(emails={"alice@example.com"})
    d = evaluate_license(make_license(), DISABLED, excl, policy, NOW)
    assert d.action is Action.KEEP and d.exclusion_status == "EXCLUDED_EMAIL"


@pytest.mark.parametrize("excl,expected", [
    (Exclusions(license_ids={"LIC0000001"}), "EXCLUDED_LICENSE_ID"),
    (Exclusions(product_codes={"ii"}), "EXCLUDED_PRODUCT"),
    (Exclusions(team_ids={1}), "EXCLUDED_TEAM"),
    (Exclusions(email_patterns=["alice@*"]), "EXCLUDED_EMAIL_PATTERN"),
    (Exclusions(service_accounts={"alice@example.com"}), "EXCLUDED_SERVICE_ACCOUNT"),
    (Exclusions(protected_users={"alice@example.com"}), "EXCLUDED_PROTECTED_USER"),
])
def test_exclusion_types(policy, excl, expected) -> None:
    assert evaluate_license(make_license(), DISABLED, excl, policy, NOW).exclusion_status == expected


def test_missing_usage_history_manual_review(policy) -> None:
    d = evaluate_license(make_license(last_seen=None), ENABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.MANUAL_REVIEW and d.usage_data_source == "UNAVAILABLE"


def test_offline_activation_code_manual_review(policy) -> None:
    d = evaluate_license(make_license(last_seen=datetime(2025, 1, 1, tzinfo=UTC), offline=True), ENABLED, NO_EXCL,
                         policy, NOW)
    assert d.action is Action.MANUAL_REVIEW


def test_usage_predating_assignment_is_not_attributed_to_current_user(policy) -> None:
    lic = make_license(last_seen=datetime(2025, 1, 1, tzinfo=UTC), assigned=datetime(2025, 6, 1, tzinfo=UTC))
    assert evaluate_license(lic, ENABLED, NO_EXCL, policy, NOW).action is Action.MANUAL_REVIEW


def test_assignment_date_is_never_used_as_usage(policy) -> None:
    lic = make_license(last_seen=None, assigned=datetime(2020, 1, 1, tzinfo=UTC))
    assert evaluate_license(lic, ENABLED, NO_EXCL, policy, NOW).action is Action.MANUAL_REVIEW


def test_recently_assigned_disabled_user_is_deferred(policy) -> None:
    lic = make_license(assigned=datetime(2026, 10, 20, tzinfo=UTC))
    d = evaluate_license(lic, DISABLED, NO_EXCL, policy, NOW)
    assert d.action is Action.MANUAL_REVIEW and "30 days" in d.explanation


def test_unassigned_and_server_licenses_skipped(policy) -> None:
    assert evaluate_license(make_license(assignee_type=AssigneeType.NONE), None, NO_EXCL, policy, NOW).action is Action.SKIP
    assert evaluate_license(make_license(assignee_type=AssigneeType.SERVER), None, NO_EXCL, policy, NOW).action is Action.SKIP


def test_policy_toggles(policy) -> None:
    off = PolicyConfig(revoke_disabled_users=False, revoke_inactive_users=False)
    assert evaluate_license(make_license(), DISABLED, NO_EXCL, off, NOW).action is Action.KEEP
    stale = make_license(last_seen=datetime(2025, 1, 1, tzinfo=UTC))
    assert evaluate_license(stale, ENABLED, NO_EXCL, off, NOW).action is Action.KEEP


# ------------------------------------------------------------ revocation workflow
def _disabled_case(ad_config, policy):
    lic = make_license("L1", email="bob@example.com")
    ad = ad_for(ad_config, [ad_user("bob", "bob@example.com", disabled=True)])
    bob = ad.lookup("bob@example.com")
    return lic, ad, evaluate_all([lic], {"bob@example.com": bob}, NO_EXCL, policy, NOW)


def test_dry_run_prevents_every_write(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic])
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=True, now=NOW)
    assert fake.revoke_calls == []
    assert decisions[0].result is Result.DRY_RUN


def test_successful_revocation_is_verified(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic])
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == ["L1"]
    assert decisions[0].result is Result.REVOKED
    assert decisions[0].verification is Verification.VERIFIED


def test_failed_revocation_is_reported(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic], RevokeOutcome.REJECTED, apply_revoke=False)
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert decisions[0].result is Result.FAILED and decisions[0].error_message


def test_revoked_but_not_confirmed_is_flagged(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic], RevokeOutcome.REVOKED, apply_revoke=False)
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert decisions[0].verification is Verification.NOT_VERIFIED


def test_uncertain_result_checks_state_instead_of_retrying(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic], RevokeOutcome.UNCERTAIN, apply_revoke=True)
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == ["L1"]  # exactly one attempt
    assert decisions[0].result is Result.REVOKED and decisions[0].verification is Verification.VERIFIED

    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic], RevokeOutcome.UNCERTAIN, apply_revoke=False)
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == ["L1"]
    assert decisions[0].result is Result.UNCERTAIN


def test_license_already_revoked_is_skipped(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([replace(lic, assignee_type=AssigneeType.NONE, assignee_email="")])
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == []
    assert decisions[0].result is Result.SKIPPED_REVALIDATION
    assert "already" in decisions[0].error_message


def test_license_reassigned_between_inventory_and_revocation(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([replace(lic, assignee_email="new.hire@example.com")])
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == []
    assert "reassigned" in decisions[0].error_message


def test_user_reenabled_before_revocation_is_not_revoked(ad_config, policy, safety) -> None:
    lic, _, decisions = _disabled_case(ad_config, policy)
    reenabled = ad_for(ad_config, [ad_user("bob", "bob@example.com", disabled=False)])
    fake = FakeJetBrains([lic])
    execute_revocations(decisions, fake, reenabled, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == []


def test_recent_usage_found_on_revalidation_prevents_revocation(ad_config, policy, safety) -> None:
    stale = make_license("L1", last_seen=datetime(2026, 1, 1, tzinfo=UTC))
    decisions = evaluate_all([stale], {"alice@example.com": ENABLED}, NO_EXCL, policy, NOW)
    assert decisions[0].action is Action.REVOKE
    fake = FakeJetBrains([replace(stale, last_seen_date=datetime(2026, 10, 31, tzinfo=UTC))])
    execute_revocations(decisions, fake, None, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == []


def test_repeated_execution_is_idempotent(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic])
    execute_revocations(decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    # Second run over a fresh inventory: the license is now unassigned and simply skipped.
    second = evaluate_all(list(fake.licenses.values()), {}, NO_EXCL, policy, NOW)
    assert second[0].action is Action.SKIP
    # Re-running the old plan also does nothing: revalidation sees the license as revoked.
    _, _, stale_plan = _disabled_case(ad_config, policy)
    execute_revocations(stale_plan, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == ["L1"]


def test_duplicate_attempts_prevented(ad_config, policy, safety) -> None:
    lic, ad, decisions = _disabled_case(ad_config, policy)
    fake = FakeJetBrains([lic])
    execute_revocations(decisions + decisions, fake, ad, NO_EXCL, policy, safety, dry_run=False, now=NOW)
    assert fake.revoke_calls == ["L1"]


def test_consecutive_failures_abort_remaining(ad_config, policy) -> None:
    ad = ad_for(ad_config, [ad_user(f"u{i}", f"u{i}@example.com", disabled=True) for i in range(5)])
    lics = [make_license(f"L{i}", email=f"u{i}@example.com") for i in range(5)]
    results = {f"u{i}@example.com": ad.lookup(f"u{i}@example.com") for i in range(5)}
    decisions = evaluate_all(lics, results, NO_EXCL, policy, NOW)
    fake = FakeJetBrains(lics, RevokeOutcome.REJECTED, apply_revoke=False)
    run = execute_revocations(decisions, fake, ad, NO_EXCL, policy, SafetyConfig(max_consecutive_revocation_failures=2),
                              dry_run=False, now=NOW)
    assert run.aborted
    assert len(fake.revoke_calls) == 2
    assert [d.result for d in decisions[2:]] == [Result.ABORTED] * 3
