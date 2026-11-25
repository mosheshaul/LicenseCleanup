"""Safety gate tests."""

from __future__ import annotations

import pytest

from conftest import NOW, make_license
from license_cleanup.config_manager import AppConfig, ExecutionConfig, SafetyConfig
from license_cleanup.jetbrains_client import InventoryMeta
from license_cleanup.license_manager import evaluate_all
from license_cleanup.models import ADLookupResult, ADStatus
from license_cleanup.safety_checks import (
    ProductionNotAllowedError,
    check_ad_health,
    check_inventory,
    check_thresholds,
    resolve_dry_run,
)


def disabled(email: str) -> ADLookupResult:
    return ADLookupResult(email, ADStatus.DISABLED, "x", "x", "mail", True)


def decisions_for(n_revoke: int, n_keep: int, policy, exclusions=None):
    from license_cleanup.config_manager import Exclusions

    lics, ad = [], {}
    for i in range(n_revoke):
        lics.append(make_license(f"R{i}", email=f"r{i}@example.com"))
        ad[f"r{i}@example.com"] = disabled(f"r{i}@example.com")
    for i in range(n_keep):
        lics.append(make_license(f"K{i}", email=f"k{i}@example.com"))
        ad[f"k{i}@example.com"] = ADLookupResult(f"k{i}@example.com", ADStatus.ENABLED, "k", "k", "mail", True)
    return evaluate_all(lics, ad, exclusions or Exclusions(), policy, NOW)


def test_mass_revocation_count_threshold_exceeded(policy) -> None:
    violations, proposed, _ = check_thresholds(decisions_for(21, 500, policy),
                                               SafetyConfig(max_revocations=20, max_revocation_percent=100))
    assert proposed == 21 and violations


def test_mass_revocation_percent_threshold_exceeded(policy) -> None:
    violations, _, assigned = check_thresholds(decisions_for(11, 89, policy),
                                               SafetyConfig(max_revocations=50, hard_max_revocations=50,
                                                            max_revocation_percent=10))
    assert assigned == 100 and any("10" in v for v in violations)


def test_within_thresholds(policy) -> None:
    violations, _, _ = check_thresholds(decisions_for(10, 90, policy),
                                        SafetyConfig(max_revocations=20, max_revocation_percent=10))
    assert violations == []


def test_incomplete_inventory_blocks() -> None:
    assert check_inventory([make_license()], [InventoryMeta(complete=False)], 1)
    assert check_inventory([], [InventoryMeta(complete=True)], 1)
    assert check_inventory([make_license()], [InventoryMeta(complete=True)], 1) == []


def test_ad_failure_rate_blocks() -> None:
    results = {f"u{i}": ADLookupResult(f"u{i}", ADStatus.ERROR if i < 2 else ADStatus.ENABLED) for i in range(10)}
    violations, failures, total = check_ad_health(results, 5)
    assert failures == 2 and total == 10 and violations
    assert check_ad_health(results, 25)[0] == []


def test_dry_run_is_default_and_production_needs_approval() -> None:
    cfg = AppConfig()
    assert resolve_dry_run(cfg, "manual", True) is True
    assert resolve_dry_run(cfg, "scheduled", False) is True  # scheduled ignores parameters
    with pytest.raises(ProductionNotAllowedError):
        resolve_dry_run(cfg, "manual", False)


def test_scheduled_production_follows_config_only() -> None:
    cfg = AppConfig(execution=ExecutionConfig(production_enabled=True, scheduled_mode="production",
                                              approved_by="ITAM CHG0001", approved_on="2027-01-01"))
    assert resolve_dry_run(cfg, "scheduled", True) is False
    cfg.execution.scheduled_mode = "dry-run"
    assert resolve_dry_run(cfg, "scheduled", False) is True
    assert resolve_dry_run(cfg, "manual", False) is False
