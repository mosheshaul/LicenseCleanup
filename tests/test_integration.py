"""End-to-end CLI tests: mocked JetBrains HTTP API + in-memory AD.

These run every pipeline stage through ``license_cleanup.main`` exactly as
Jenkins does. No real network or directory is contacted.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import responses

from conftest import BASE_URL, FAKE_CUSTOMER, FAKE_TOKEN, FakeLDAPConnection, ad_user, license_json
from license_cleanup import main as cli
from license_cleanup.ad_client import ADClient

CONFIG = """
log_level: INFO
execution:
  production_enabled: {prod}
  scheduled_mode: {sched}
  approved_by: "{approved_by}"
  approved_on: "{approved_on}"
jetbrains:
  base_url: {base}
  page_size: 100
  max_retries: 0
active_directory:
  domain: corp.example.test
  server: dc01.corp.example.test
  base_dn: "DC=corp,DC=example,DC=test"
  ca_certs_file: null
safety:
  max_revocations: {max_rev}
  hard_max_revocations: 50
  max_revocation_percent: 100
reporting:
  output_dir: {reports}
"""

DIRECTORY = [ad_user("bob", "bob@example.com", disabled=True), ad_user("alice", "alice@example.com")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    def write(prod=False, sched="dry-run", max_rev=20):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(CONFIG.format(
            prod=str(prod).lower(), sched=sched, base=BASE_URL, max_rev=max_rev, reports=tmp_path / "reports",
            approved_by="ITAM CHG0001" if prod else "", approved_on="2027-01-01" if prod else "",
        ))
        return cfg

    monkeypatch.setenv("JETBRAINS_API_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("JETBRAINS_CUSTOMER_CODE", FAKE_CUSTOMER)
    monkeypatch.setenv("AD_BIND_USER", "svc-ldap-reader@corp.example.test")
    monkeypatch.setenv("AD_BIND_PASSWORD", "fake-ad-password")
    monkeypatch.setattr(cli, "AD_FACTORY", lambda config, secrets: ADClient(
        config.active_directory, secrets.ad_bind_user, secrets.ad_bind_password,
        connection_factory=lambda *_: FakeLDAPConnection(DIRECTORY)))
    return write


def mock_api(revoked: set[str] | None = None) -> None:
    licenses = [
        license_json("L-BOB", "bob@example.com"),                                  # disabled -> revoke
        license_json("L-ALICE-II", "alice@example.com", "II", "2026-11-01T00:00:00Z"),
        license_json("L-ALICE-PC", "alice@example.com", "PC", "2025-01-01T00:00:00Z"),  # inactive -> revoke
        license_json("L-NEW", "nobody@example.com"),                               # not in AD -> review
    ]
    state = {lic["licenseId"]: lic for lic in licenses}
    revoked = revoked if revoked is not None else set()
    responses.get(f"{BASE_URL}/token", json={"type": "CUSTOMER", "role": "ADMIN", "teams": []})
    responses.get(f"{BASE_URL}/products", json=[{"code": "II", "name": "IntelliJ IDEA Ultimate"}])

    def list_cb(request):
        assigned = request.params.get("assigned") == "true"
        items = [lic for lic in state.values() if (lic["assignee"] is not None) == assigned]
        return 200, {"X-Total-Count": str(len(items))}, json.dumps(items)

    def get_cb(request):
        lid = request.path_url.rsplit("/", 1)[1]
        return (200, {}, json.dumps(state[lid])) if lid in state else (404, {}, "{}")

    def revoke_cb(request):
        lid = request.params["licenseId"]
        revoked.add(lid)
        state[lid] = {**state[lid], "assignee": None, "isAvailableToAssign": True}
        return 200, {}, json.dumps({"licenseIds": [lid]})

    responses.add_callback(responses.GET, f"{BASE_URL}/customer/licenses", callback=list_cb)
    for lid in state:
        responses.add_callback(responses.GET, f"{BASE_URL}/customer/licenses/{lid}", callback=get_cb)
    responses.add_callback(responses.POST, f"{BASE_URL}/customer/licenses/revoke", callback=revoke_cb)


def run(cfg: Path, tmp_path: Path, *extra: str) -> int:
    return cli.main(["run", "--config", str(cfg), "--state-dir", str(tmp_path / "state"),
                     "--log-dir", str(tmp_path / "logs"), *extra])


def report_rows(tmp_path: Path) -> list[dict[str, str]]:
    files = list((tmp_path / "reports").rglob("license_audit_*.csv"))
    assert len(files) == 1
    with files[0].open() as handle:
        return list(csv.DictReader(handle))


def summary(tmp_path: Path) -> dict:
    return json.loads(next((tmp_path / "reports").rglob("execution_summary_*.json")).read_text())


@responses.activate
def test_dry_run_end_to_end_never_writes(env, tmp_path) -> None:
    revoked: set[str] = set()
    mock_api(revoked)
    code = run(env(), tmp_path, "--dry-run", "false")  # requesting production without approval
    assert code == cli.EXIT_CRITICAL
    assert revoked == set()

    mock_api(revoked)
    code = run(env(), tmp_path, "--dry-run", "true")
    assert code == cli.EXIT_OK
    assert revoked == set()
    assert not [c for c in responses.calls if c.request.method == "POST"]
    rows = {r["LicenseID"]: r for r in report_rows(tmp_path)}
    assert rows["L-BOB"]["ProposedAction"] == "REVOKE" and rows["L-BOB"]["Result"] == "DRY_RUN_NO_CHANGE"
    assert rows["L-ALICE-PC"]["RevocationReason"] == "PRODUCT_INACTIVE"
    assert rows["L-ALICE-II"]["ProposedAction"] == "KEEP"
    assert rows["L-NEW"]["ProposedAction"] == "MANUAL_REVIEW"
    assert summary(tmp_path)["mode"] == "DRY_RUN"


@responses.activate
def test_production_end_to_end_revokes_and_verifies(env, tmp_path) -> None:
    revoked: set[str] = set()
    mock_api(revoked)
    code = run(env(prod=True), tmp_path, "--dry-run", "false")
    assert code == cli.EXIT_OK
    assert revoked == {"L-BOB", "L-ALICE-PC"}
    rows = {r["LicenseID"]: r for r in report_rows(tmp_path)}
    assert rows["L-BOB"]["Result"] == "REVOKED" and rows["L-BOB"]["VerificationStatus"] == "VERIFIED"
    s = summary(tmp_path)
    assert s["totals"]["successfully_revoked"] == 2 and s["overall_status"] == "SUCCESS"
    log_text = "".join(p.read_text() for p in (tmp_path / "logs").glob("*.log"))
    assert FAKE_TOKEN not in log_text and "fake-ad-password" not in log_text


@responses.activate
def test_scheduled_run_ignores_parameters(env, tmp_path) -> None:
    revoked: set[str] = set()
    mock_api(revoked)
    # Config allows production but scheduled_mode is dry-run: parameters cannot force revocation.
    code = run(env(prod=True, sched="dry-run"), tmp_path, "--trigger", "scheduled", "--dry-run", "false")
    assert code == cli.EXIT_OK and revoked == set()


@responses.activate
def test_safety_threshold_blocks_all_revocations(env, tmp_path) -> None:
    revoked: set[str] = set()
    mock_api(revoked)
    code = run(env(prod=True, max_rev=1), tmp_path, "--dry-run", "false")
    assert code == cli.EXIT_PARTIAL
    assert revoked == set()
    assert summary(tmp_path)["overall_status"] == "SAFETY_BLOCKED"


@responses.activate
def test_ad_unavailable_aborts_without_revocations(env, tmp_path, monkeypatch) -> None:
    revoked: set[str] = set()
    mock_api(revoked)
    monkeypatch.setattr(cli, "AD_FACTORY", lambda config, secrets: ADClient(
        config.active_directory, "u", "p", connection_factory=lambda *_: FakeLDAPConnection([], fail_open=True)))
    code = run(env(prod=True), tmp_path, "--dry-run", "false")
    assert code == cli.EXIT_CRITICAL
    assert revoked == set()


@responses.activate
def test_api_auth_failure_is_critical(env, tmp_path) -> None:
    responses.get(f"{BASE_URL}/token", status=401, json={"code": "UNAUTHORIZED", "description": "bad token"})
    code = run(env(), tmp_path)
    assert code == cli.EXIT_CRITICAL
