"""Command-line entry point.

The pipeline is split into stages so Jenkins can show each step separately
and bind credentials only where they are needed. Stages exchange state via
JSON files in ``--state-dir`` (deleted by the pipeline's cleanup step).

Exit codes: 0 = success, 1 = partial failure / safety gate blocked (Jenkins
UNSTABLE), 2 = critical failure (Jenkins FAILURE).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .ad_client import ADAuthError, ADClient, ADConnectionError, ADSearchError
from .config_manager import AppConfig, ConfigError, Secrets, apply_overrides, load_config, validate_secrets
from .jetbrains_client import InventoryMeta, JetBrainsAPIError, JetBrainsAuthError, JetBrainsClient
from .license_manager import evaluate_all, execute_revocations, lookup_ad_users, verify_revocation
from .logger import setup_logging
from .models import Action, ADLookupResult, Decision, License, Result, Verification, parse_timestamp
from .notification_manager import notify
from .report_generator import build_summary, write_csv, write_json
from .safety_checks import ProductionNotAllowedError, SafetyReport, resolve_dry_run, run_safety_checks

log = logging.getLogger("license_cleanup")

EXIT_OK, EXIT_PARTIAL, EXIT_CRITICAL = 0, 1, 2


class CriticalError(Exception):
    """Any failure that must stop the run and fail the build."""


# ----------------------------------------------------------------- state I/O
class State:
    """JSON state shared between pipeline stages."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.json"

    def save(self, name: str, data: Any) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        fd = os.open(self._path(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1)

    def load(self, name: str) -> Any:
        path = self._path(name)
        if not path.exists():
            raise CriticalError(f"Required state '{name}' is missing; did an earlier stage fail?")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def add_error(self, message: str, critical: bool = False) -> None:
        errors = self.load("errors") if self.exists("errors") else []
        errors.append({"message": message, "critical": critical})
        self.save("errors", errors)


# -------------------------------------------------------------- dependencies
def make_jetbrains_client(config: AppConfig, secrets: Secrets) -> JetBrainsClient:
    validate_secrets(secrets, need_jetbrains=True, need_ad=False)
    j = config.jetbrains
    return JetBrainsClient(
        j.base_url, secrets.jetbrains_api_token, secrets.jetbrains_customer_code,
        connect_timeout=j.connect_timeout_seconds, read_timeout=j.read_timeout_seconds,
        max_retries=j.max_retries, backoff_base=j.backoff_base_seconds, backoff_max=j.backoff_max_seconds,
        ca_bundle=j.ca_bundle, page_size=j.page_size, max_pages=j.max_pages,
        require_total_count=j.require_total_count_header,
    )


def make_ad_client(config: AppConfig, secrets: Secrets) -> ADClient:
    validate_secrets(secrets, need_jetbrains=False, need_ad=True)
    return ADClient(config.active_directory, secrets.ad_bind_user, secrets.ad_bind_password)


# These factories can be replaced in integration tests.
JETBRAINS_FACTORY: Callable[[AppConfig, Secrets], JetBrainsClient] = make_jetbrains_client
AD_FACTORY: Callable[[AppConfig, Secrets], ADClient] = make_ad_client


# ------------------------------------------------------------------ helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _context(state: State) -> dict[str, Any]:
    return state.load("context")


def _config_for_run(args: argparse.Namespace, state: State) -> AppConfig:
    config = load_config(args.config, args.exclusions)
    if state.exists("context"):
        apply_overrides(config, _context(state).get("overrides", {}))
    return config


def _load_decisions(state: State) -> list[Decision]:
    return [Decision.from_dict(d) for d in state.load("decisions")]


def _save_decisions(state: State, decisions: list[Decision]) -> None:
    state.save("decisions", [d.to_dict() for d in decisions])


def _bool(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError(f"Expected true/false, got {value!r}")


def _optional_number(kind: Callable[[str], Any]) -> Callable[[str], Any]:
    """argparse type: an empty string (blank Jenkins parameter) means "use the config value"."""

    def parse(value: str) -> Any:
        if value is None or value.strip() == "":
            return None
        try:
            return kind(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Expected a number, got {value!r}") from exc

    return parse


# ------------------------------------------------------------------- stages
def cmd_init(args: argparse.Namespace, state: State) -> int:
    """Create the execution context and resolve dry-run vs production."""
    config = load_config(args.config, args.exclusions)
    overrides: dict[str, Any] = {}
    if args.trigger == "manual":
        overrides = {
            "inactivity_months": args.inactivity_months,
            "revoke_disabled_users": _bool(args.revoke_disabled_users),
            "revoke_inactive_users": _bool(args.revoke_inactive_users),
            "max_revocations": args.max_revocations,
            "max_revocation_percent": args.max_revocation_percent,
            "log_level": args.log_level,
        }
        overrides = {k: v for k, v in overrides.items() if v is not None}
        apply_overrides(config, overrides)
    else:
        log.info("Scheduled run: build parameters are ignored; using the approved configuration file only")
    requested_dry_run = _bool(args.dry_run)
    dry_run = resolve_dry_run(config, args.trigger, True if requested_dry_run is None else requested_dry_run)
    execution_id = args.execution_id or f"{_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    state.save("context", {
        "execution_id": execution_id,
        "started_at": _now().isoformat(),
        "trigger": args.trigger,
        "dry_run": dry_run,
        "overrides": overrides,
    })
    state.save("errors", [])
    log.info("Execution %s initialised: trigger=%s mode=%s", execution_id, args.trigger,
             "DRY_RUN" if dry_run else "PRODUCTION")
    if not dry_run:
        log.warning("PRODUCTION MODE: eligible licenses will be revoked (approved by %s on %s)",
                    config.execution.approved_by, config.execution.approved_on)
    return EXIT_OK


def cmd_validate_config(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    log.info("Configuration valid: inactivity=%d months, max_revocations=%d, max_percent=%s, exclusions: %d emails, "
             "%d license ids, %d products", config.policy.inactivity_months, config.safety.max_revocations,
             config.safety.max_revocation_percent, len(config.exclusions.emails), len(config.exclusions.license_ids),
             len(config.exclusions.product_codes))
    return EXIT_OK


def cmd_check_jetbrains(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    client = JETBRAINS_FACTORY(config, Secrets.from_env())
    info = client.get_token_info()
    log.info("JetBrains API reachable: token type=%s role=%s teams=%d", info.get("type"), info.get("role"),
             len(info.get("teams") or []))
    return EXIT_OK


def cmd_check_ad(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    with AD_FACTORY(config, Secrets.from_env()) as ad:
        ad.health_check()
    log.info("Active Directory reachable and service account bind succeeded")
    return EXIT_OK


def cmd_inventory(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    client = JETBRAINS_FACTORY(config, Secrets.from_env())
    products = client.list_products()
    licenses, metas = client.list_licenses(config.jetbrains.team_ids or None)
    state.save("inventory", {
        "licenses": [lic.to_dict() for lic in licenses],
        "metas": [m.__dict__ for m in metas],
        "products_catalog_size": len(products),
    })
    assigned = sum(1 for lic in licenses if lic.is_assigned)
    log.info("Inventory: %d licenses (%d assigned) across %d products", len(licenses), assigned,
             len({lic.product_code for lic in licenses}))
    return EXIT_OK


def _load_inventory(state: State) -> tuple[list[License], list[InventoryMeta], int | None]:
    inv = state.load("inventory")
    return ([License.from_dict(d) for d in inv["licenses"]], [InventoryMeta(**m) for m in inv["metas"]],
            inv.get("products_catalog_size"))


def cmd_match_ad(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    licenses, _, _ = _load_inventory(state)
    with AD_FACTORY(config, Secrets.from_env()) as ad:
        results = lookup_ad_users(licenses, ad)
    state.save("ad_results", {k: v.to_dict() for k, v in results.items()})
    by_status: dict[str, int] = {}
    for r in results.values():
        by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
    log.info("AD lookups for %d users: %s", len(results), by_status)
    return EXIT_OK


def _load_ad(state: State) -> dict[str, ADLookupResult]:
    return {k: ADLookupResult.from_dict(v) for k, v in state.load("ad_results").items()}


def cmd_analyze(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    licenses, _, _ = _load_inventory(state)
    decisions = evaluate_all(licenses, _load_ad(state), config.exclusions, config.policy, _now())
    _save_decisions(state, decisions)
    counts: dict[str, int] = {}
    for d in decisions:
        counts[d.action.value] = counts.get(d.action.value, 0) + 1
    log.info("Analysis complete: %s", counts)
    return EXIT_OK


def cmd_plan(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    ctx = _context(state)
    decisions = _load_decisions(state)
    candidates = [d for d in decisions if d.action is Action.REVOKE]
    out = Path(config.reporting.output_dir) / ctx["execution_id"]
    write_csv(out / "proposed_revocation_plan.csv", candidates, ctx["execution_id"], _now(), ctx["dry_run"])
    log.info("Proposed revocation plan: %d licenses", len(candidates))
    return EXIT_OK


def cmd_safety_check(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    licenses, metas, _ = _load_inventory(state)
    report = run_safety_checks(licenses, metas, _load_ad(state), _load_decisions(state), config)
    state.save("safety", report.to_dict())
    if not report.ok:
        for v in report.violations:
            log.error("SAFETY GATE: %s", v)
        log.error("Revocations are blocked for this run. Reports will still be generated.")
        return EXIT_PARTIAL
    log.info("Safety checks passed (%d proposed of %d assigned)", report.proposed_revocations,
             report.assigned_licenses)
    return EXIT_OK


def cmd_revoke(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    ctx = _context(state)
    decisions = _load_decisions(state)
    safety = state.load("safety") if state.exists("safety") else None
    if ctx["dry_run"]:
        execute_revocations(decisions, None, None, config.exclusions, config.policy, config.safety,
                            dry_run=True, now=_now())
        _save_decisions(state, decisions)
        log.info("Dry run: no licenses were revoked")
        return EXIT_OK
    if not safety or not safety.get("ok"):
        log.error("Safety gate did not pass; refusing to revoke")
        return EXIT_PARTIAL
    secrets = Secrets.from_env()
    client = JETBRAINS_FACTORY(config, secrets)
    try:
        with AD_FACTORY(config, secrets) as ad:
            run = execute_revocations(decisions, client, ad, config.exclusions, config.policy, config.safety,
                                      dry_run=False, now=_now())
    finally:
        # Persist progress even if a critical error (e.g. token revoked mid-run) stops the loop,
        # so the audit report shows exactly which licenses were already revoked.
        _save_decisions(state, decisions)
    if run.aborted:
        state.add_error(run.abort_reason)
    failed = sum(1 for d in decisions if d.result in (Result.FAILED, Result.UNCERTAIN, Result.ABORTED))
    revoked = sum(1 for d in decisions if d.result is Result.REVOKED)
    log.info("Revocation finished: %d revoked, %d failed/uncertain/aborted", revoked, failed)
    return EXIT_PARTIAL if failed or run.aborted else EXIT_OK


def cmd_verify(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    ctx = _context(state)
    decisions = _load_decisions(state)
    pending = [d for d in decisions if d.result in (Result.REVOKED, Result.UNCERTAIN)]
    if ctx["dry_run"] or not pending:
        log.info("Nothing to verify")
        return EXIT_OK
    client = JETBRAINS_FACTORY(config, Secrets.from_env())
    unverified = 0
    for d in pending:
        d.verification = verify_revocation(client, d.license.license_id, d.license.assignee_email)
        if d.verification is Verification.VERIFIED and d.result is Result.UNCERTAIN:
            d.result, d.actual_action = Result.REVOKED, "REVOKED"
        if d.verification is not Verification.VERIFIED:
            unverified += 1
    _save_decisions(state, decisions)
    log.info("Verification: %d checked, %d not verified", len(pending), unverified)
    return EXIT_PARTIAL if unverified else EXIT_OK


def _overall_status(state: State, decisions: list[Decision], safety: dict[str, Any] | None) -> tuple[str, int]:
    errors = state.load("errors") if state.exists("errors") else []
    if any(e.get("critical") for e in errors) or not state.exists("decisions"):
        return "CRITICAL_FAILURE", EXIT_CRITICAL
    if safety and not safety.get("ok"):
        return "SAFETY_BLOCKED", EXIT_PARTIAL
    if errors or any(d.result in (Result.FAILED, Result.UNCERTAIN, Result.ABORTED) for d in decisions):
        return "PARTIAL_FAILURE", EXIT_PARTIAL
    if any(d.result is Result.REVOKED and d.verification is not Verification.VERIFIED for d in decisions):
        return "PARTIAL_FAILURE", EXIT_PARTIAL
    return "SUCCESS", EXIT_OK


def cmd_report(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    ctx = _context(state)
    decisions = _load_decisions(state) if state.exists("decisions") else []
    safety = state.load("safety") if state.exists("safety") else None
    status, code = _overall_status(state, decisions, safety)
    catalog = state.load("inventory").get("products_catalog_size") if state.exists("inventory") else None
    started = parse_timestamp(ctx["started_at"]) or _now()
    out = Path(config.reporting.output_dir) / ctx["execution_id"]
    stamp = f"{started:%Y%m%dT%H%M%SZ}"
    write_csv(out / f"license_audit_{stamp}.csv", decisions, ctx["execution_id"], _now(), ctx["dry_run"])
    errors = [e["message"] for e in (state.load("errors") if state.exists("errors") else [])]
    summary = build_summary(
        decisions, execution_id=ctx["execution_id"], started_at=started, finished_at=_now(),
        dry_run=ctx["dry_run"], trigger=ctx["trigger"], products_catalog_size=catalog, safety=safety,
        status=status, pricing=config.reporting.pricing, pricing_source=config.reporting.pricing_source,
        currency=config.reporting.currency, errors=errors,
    )
    write_json(out / f"execution_summary_{stamp}.json", summary)
    state.save("summary", summary)
    log.info("Reports written to %s (status %s)", out, status)
    return code


def cmd_notify(args: argparse.Namespace, state: State) -> int:
    config = _config_for_run(args, state)
    if state.exists("summary"):
        summary = state.load("summary")
    else:  # an early stage failed before reports: still notify
        ctx = state.load("context") if state.exists("context") else {}
        errors = state.load("errors") if state.exists("errors") else []
        summary = {"execution_id": ctx.get("execution_id", ""), "trigger": ctx.get("trigger", ""),
                   "mode": "DRY_RUN" if ctx.get("dry_run", True) else "PRODUCTION",
                   "started_at": ctx.get("started_at", ""), "overall_status": "CRITICAL_FAILURE",
                   "totals": {}, "errors": [e["message"] for e in errors]}
    build_url = os.environ.get("BUILD_URL", "")
    report_url = f"{build_url}artifact/" if build_url else ""
    errors = notify(config.notifications, Secrets.from_env(), summary, build_url, report_url)
    return EXIT_PARTIAL if errors else EXIT_OK


def cmd_run(args: argparse.Namespace, state: State) -> int:
    """Run every stage in order (local use)."""
    worst = EXIT_OK
    stages = [cmd_init, cmd_validate_config, cmd_check_jetbrains, cmd_check_ad, cmd_inventory, cmd_match_ad,
              cmd_analyze, cmd_plan, cmd_safety_check, cmd_revoke, cmd_verify]
    try:
        for stage in stages:
            code = stage(args, state)
            worst = max(worst, code)
            if code == EXIT_CRITICAL:
                break
    except Exception as exc:  # recorded and reported, then re-raised as critical below
        _record_critical(state, exc)
        worst = EXIT_CRITICAL
    if state.exists("context"):
        worst = max(worst, _guard(cmd_report, args, state))
        _guard(cmd_notify, args, state)
    return worst


COMMANDS: dict[str, Callable[[argparse.Namespace, State], int]] = {
    "init": cmd_init,
    "validate-config": cmd_validate_config,
    "check-jetbrains": cmd_check_jetbrains,
    "check-ad": cmd_check_ad,
    "inventory": cmd_inventory,
    "match-ad": cmd_match_ad,
    "analyze": cmd_analyze,
    "plan": cmd_plan,
    "safety-check": cmd_safety_check,
    "revoke": cmd_revoke,
    "verify": cmd_verify,
    "report": cmd_report,
    "notify": cmd_notify,
    "run": cmd_run,
}


def _record_critical(state: State, exc: BaseException) -> None:
    if isinstance(exc, (JetBrainsAuthError, ADAuthError)):
        message = f"Authentication/permission failure: {exc}"
    elif isinstance(exc, (ADConnectionError, ADSearchError)):
        message = f"Active Directory failure, revocations aborted: {exc}"
    elif isinstance(exc, JetBrainsAPIError):
        message = f"JetBrains API failure: {exc}"
    elif isinstance(exc, (ConfigError, ProductionNotAllowedError)):
        message = str(exc)
    else:
        message = f"Unexpected error: {type(exc).__name__}: {exc}"
    log.error(message)
    try:
        state.add_error(message, critical=True)
    except Exception:  # pragma: no cover  # already logged above
        log.debug("Could not persist critical error to state")


def _guard(func: Callable[[argparse.Namespace, State], int], args: argparse.Namespace, state: State) -> int:
    try:
        return func(args, state)
    except Exception as exc:
        log.debug("Stage failed", exc_info=True)
        _record_critical(state, exc)
        return EXIT_CRITICAL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="license-cleanup", description="JetBrains license cleanup automation")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--exclusions", default=None, help="Override exclusions file path")
    parser.add_argument("--state-dir", default=".state")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--execution-id", default=None)
    parser.add_argument("--trigger", choices=["manual", "scheduled"], default="manual")
    parser.add_argument("--dry-run", default="true", help="true/false (manual runs only)")
    parser.add_argument("--inactivity-months", type=_optional_number(int), default=None)
    parser.add_argument("--revoke-disabled-users", default=None)
    parser.add_argument("--revoke-inactive-users", default=None)
    parser.add_argument("--max-revocations", type=_optional_number(int), default=None)
    parser.add_argument("--max-revocation-percent", type=_optional_number(float), default=None)
    parser.add_argument("--log-level", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = State(Path(args.state_dir))
    execution_id = args.execution_id or ""
    if state.exists("context"):
        try:
            execution_id = _context(state).get("execution_id", execution_id)
        except Exception:  # unreadable context only affects the log prefix
            execution_id = execution_id or ""
    setup_logging(args.log_level or "INFO", args.log_dir, execution_id)
    if args.command == "run":
        return cmd_run(args, state)
    return _guard(COMMANDS[args.command], args, state)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
