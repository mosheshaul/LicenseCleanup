"""Report generation tests."""

from __future__ import annotations

import csv
import json
import stat

from conftest import NOW, make_license
from license_cleanup.config_manager import Exclusions
from license_cleanup.license_manager import evaluate_all
from license_cleanup.models import ADLookupResult, ADStatus, Result, Verification
from license_cleanup.report_generator import CSV_COLUMNS, build_summary, sanitize_cell, write_csv, write_json


def _decisions(policy):
    lics = [make_license("L1", email="bob@example.com"), make_license("L2", email="=HYPERLINK(\"x\")@example.com")]
    ad = {"bob@example.com": ADLookupResult("bob@example.com", ADStatus.DISABLED, "bob", "bob@corp", "mail", True)}
    return evaluate_all(lics, ad, Exclusions(), policy, NOW)


def test_formula_injection_is_neutralised() -> None:
    for payload in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1"):
        assert sanitize_cell(payload).startswith("'")
    assert sanitize_cell("-5") == "-5"
    assert sanitize_cell("normal") == "normal"


def test_csv_has_required_columns_and_is_private(tmp_path, policy) -> None:
    path = write_csv(tmp_path / "audit.csv", _decisions(policy), "EXEC1", NOW, True)
    with path.open() as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert rows[0]["ProposedAction"] == "REVOKE" and rows[0]["DryRun"] == "true"
    assert rows[1]["EmailAddress"].startswith("'=")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_csv_contains_no_secrets(tmp_path, policy) -> None:
    path = write_csv(tmp_path / "audit.csv", _decisions(policy), "EXEC1", NOW, True)
    text = path.read_text()
    assert "fake-token" not in text and "password" not in text.lower()


def test_summary_counts_and_breakdown(policy, tmp_path) -> None:
    decisions = _decisions(policy)
    decisions[0].result, decisions[0].verification = Result.REVOKED, Verification.VERIFIED
    summary = build_summary(decisions, execution_id="E", started_at=NOW, finished_at=NOW, dry_run=False,
                            trigger="scheduled", products_catalog_size=40, safety={"ok": True}, status="SUCCESS")
    t = summary["totals"]
    assert t["licenses_discovered"] == 2 and t["successfully_revoked"] == 1 and t["disabled_users"] == 1
    assert t["not_revoked_due_to_lookup_failure"] == 1  # second user was never looked up
    assert summary["revoked_by_product_and_reason"] == {"IntelliJ IDEA Ultimate": {"AD_ACCOUNT_DISABLED": 1}}
    assert summary["cost"]["subscription_cost_reduction"] is None
    write_json(tmp_path / "s.json", summary)
    assert json.loads((tmp_path / "s.json").read_text())["overall_status"] == "SUCCESS"
    assert "bob@example.com" not in json.dumps(summary)


def test_pricing_only_when_provided(policy) -> None:
    decisions = _decisions(policy)
    summary = build_summary(decisions, execution_id="E", started_at=NOW, finished_at=NOW, dry_run=True,
                            trigger="manual", products_catalog_size=None, safety=None, status="SUCCESS",
                            pricing={"II": 100.0}, pricing_source="FY27 quote")
    assert summary["cost"]["estimated_value_of_reclaimed_capacity"] == 100.0
    assert summary["cost"]["pricing_source"] == "FY27 quote"


def test_formula_after_leading_whitespace_is_neutralised() -> None:
    assert sanitize_cell("  =HYPERLINK(\"x\")").startswith("'")
    assert sanitize_cell("\t+cmd").startswith("'")
