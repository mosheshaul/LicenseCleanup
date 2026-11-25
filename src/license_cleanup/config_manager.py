"""Configuration loading and validation.

Non-sensitive settings come from YAML files. Secrets come exclusively from
environment variables injected by Jenkins credentials binding (never from
YAML, never from command-line arguments).
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .logger import register_secret

# Environment variable NAMES used for secrets (values injected by Jenkins). Not secrets themselves.
ENV_JETBRAINS_TOKEN = "JETBRAINS_API_TOKEN"  # env var name, not a value  # nosec B105
ENV_JETBRAINS_CUSTOMER_CODE = "JETBRAINS_CUSTOMER_CODE"
ENV_AD_BIND_USER = "AD_BIND_USER"
ENV_AD_BIND_PASSWORD = "AD_BIND_PASSWORD"  # env var name, not a value  # nosec B105
ENV_SLACK_WEBHOOK = "SLACK_WEBHOOK_URL"
ENV_SMTP_USER = "SMTP_USER"
ENV_SMTP_PASSWORD = "SMTP_PASSWORD"  # env var name, not a value  # nosec B105


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass
class ExecutionConfig:
    production_enabled: bool = False
    scheduled_mode: str = "dry-run"
    approved_by: str = ""
    approved_on: str = ""


@dataclass
class PolicyConfig:
    inactivity_months: int = 6
    revoke_disabled_users: bool = True
    revoke_inactive_users: bool = True
    min_assignment_age_days: int = 30


@dataclass
class JetBrainsConfig:
    base_url: str = "https://account.jetbrains.com/api/v1"
    team_ids: list[int] = field(default_factory=list)
    page_size: int = 100
    max_pages: int = 1000
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 60.0
    max_retries: int = 4
    backoff_base_seconds: float = 2.0
    backoff_max_seconds: float = 60.0
    ca_bundle: str | None = None
    require_total_count_header: bool = True
    expected_min_licenses: int = 1


@dataclass
class ADConfig:
    domain: str = ""
    server: str = ""
    port: int = 636
    base_dn: str = ""
    search_scope: str = "SUBTREE"
    connect_timeout_seconds: float = 10.0
    search_timeout_seconds: float = 30.0
    ca_certs_file: str | None = None
    allow_samaccountname_fallback: bool = True
    external_domains: list[str] = field(default_factory=list)
    email_domain_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class SafetyConfig:
    max_revocations: int = 20
    hard_max_revocations: int = 50
    max_revocation_percent: float = 10.0
    max_ad_lookup_failure_percent: float = 5.0
    max_consecutive_revocation_failures: int = 3


@dataclass
class ReportingConfig:
    output_dir: str = "reports"
    currency: str = "USD"
    pricing: dict[str, float] = field(default_factory=dict)
    pricing_source: str = ""


@dataclass
class SlackConfig:
    enabled: bool = False
    channel_is_private: bool = True


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    use_starttls: bool = True
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    timeout_seconds: float = 30.0


@dataclass
class NotificationConfig:
    slack: SlackConfig = field(default_factory=SlackConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    include_product_breakdown: bool = True


@dataclass
class Exclusions:
    """Licenses and users that must never be revoked by this automation."""

    emails: set[str] = field(default_factory=set)
    email_patterns: list[str] = field(default_factory=list)
    service_accounts: set[str] = field(default_factory=set)
    protected_users: set[str] = field(default_factory=set)
    license_ids: set[str] = field(default_factory=set)
    product_codes: set[str] = field(default_factory=set)
    team_ids: set[int] = field(default_factory=set)
    team_names: set[str] = field(default_factory=set)

    def match(self, email: str, license_id: str, product_code: str, team_id: int | None, team_name: str) -> str:
        """Return a human-readable exclusion reason, or ``""`` if not excluded."""
        email_n = email.strip().casefold()
        if license_id in self.license_ids:
            return "EXCLUDED_LICENSE_ID"
        if email_n and email_n in self.protected_users:
            return "EXCLUDED_PROTECTED_USER"
        if email_n and email_n in self.service_accounts:
            return "EXCLUDED_SERVICE_ACCOUNT"
        if email_n and email_n in self.emails:
            return "EXCLUDED_EMAIL"
        if email_n and any(fnmatch.fnmatchcase(email_n, p) for p in self.email_patterns):
            return "EXCLUDED_EMAIL_PATTERN"
        if product_code.casefold() in self.product_codes:
            return "EXCLUDED_PRODUCT"
        if team_id is not None and team_id in self.team_ids:
            return "EXCLUDED_TEAM"
        if team_name and team_name.casefold() in self.team_names:
            return "EXCLUDED_TEAM"
        return ""


@dataclass
class Secrets:
    """Secrets read from the environment. Never serialised or logged."""

    jetbrains_api_token: str = field(default="", repr=False)
    jetbrains_customer_code: str = field(default="", repr=False)
    ad_bind_user: str = field(default="", repr=False)
    ad_bind_password: str = field(default="", repr=False)
    slack_webhook_url: str = field(default="", repr=False)
    smtp_user: str = field(default="", repr=False)
    smtp_password: str = field(default="", repr=False)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Secrets":
        source = os.environ if env is None else env
        secrets = cls(
            jetbrains_api_token=source.get(ENV_JETBRAINS_TOKEN, ""),
            jetbrains_customer_code=source.get(ENV_JETBRAINS_CUSTOMER_CODE, ""),
            ad_bind_user=source.get(ENV_AD_BIND_USER, ""),
            ad_bind_password=source.get(ENV_AD_BIND_PASSWORD, ""),
            slack_webhook_url=source.get(ENV_SLACK_WEBHOOK, ""),
            smtp_user=source.get(ENV_SMTP_USER, ""),
            smtp_password=source.get(ENV_SMTP_PASSWORD, ""),
        )
        for value in (
            secrets.jetbrains_api_token,
            secrets.jetbrains_customer_code,
            secrets.ad_bind_password,
            secrets.slack_webhook_url,
            secrets.smtp_password,
        ):
            register_secret(value)
        return secrets


@dataclass
class AppConfig:
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    jetbrains: JetBrainsConfig = field(default_factory=JetBrainsConfig)
    active_directory: ADConfig = field(default_factory=ADConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    exclusions: Exclusions = field(default_factory=Exclusions)
    log_level: str = "INFO"


_SECRET_KEY_HINTS = ("password", "token", "secret", "api_key", "apikey", "webhook", "customer_code")


def _reject_secrets_in_yaml(data: Any, path: str = "") -> None:
    """Refuse configuration files that appear to contain secrets."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_l = str(key).lower()
            sub = f"{path}.{key}" if path else str(key)
            if any(h in key_l for h in _SECRET_KEY_HINTS) and value not in (None, "", {}, []) and not isinstance(value, (bool, dict)):
                raise ConfigError(
                    f"Configuration key '{sub}' looks like a secret. Secrets must come from Jenkins credentials "
                    "(environment variables), never from YAML files."
                )
            _reject_secrets_in_yaml(value, sub)
    elif isinstance(data, list):
        for item in data:
            _reject_secrets_in_yaml(item, path)


def _build(dc_type: type, data: dict[str, Any] | None, section: str) -> Any:
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError(f"Section '{section}' must be a mapping")
    known = {f for f in dc_type.__dataclass_fields__}  # type: ignore[attr-defined]
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"Unknown key(s) in '{section}': {', '.join(sorted(unknown))}")
    return dc_type(**data)


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Configuration file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Configuration file {path} must contain a mapping")
    _reject_secrets_in_yaml(data)
    return data


def load_exclusions(path: Path | None) -> Exclusions:
    """Load the exclusion list. A missing path yields an empty list."""
    if path is None or not path.exists():
        return Exclusions()
    data = _load_yaml(path)
    allowed = {"emails", "email_patterns", "service_accounts", "protected_users", "license_ids",
               "product_codes", "team_ids", "team_names"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown key(s) in exclusions file: {', '.join(sorted(unknown))}")

    def emails(key: str) -> set[str]:
        return {str(v).strip().casefold() for v in (data.get(key) or [])}

    try:
        team_ids = {int(v) for v in (data.get("team_ids") or [])}
    except (TypeError, ValueError) as exc:
        raise ConfigError("exclusions.team_ids must contain integers") from exc
    return Exclusions(
        emails=emails("emails"),
        email_patterns=[str(v).strip().casefold() for v in (data.get("email_patterns") or [])],
        service_accounts=emails("service_accounts"),
        protected_users=emails("protected_users"),
        license_ids={str(v).strip() for v in (data.get("license_ids") or [])},
        product_codes={str(v).strip().casefold() for v in (data.get("product_codes") or [])},
        team_ids=team_ids,
        team_names={str(v).strip().casefold() for v in (data.get("team_names") or [])},
    )


def load_config(config_path: str | Path, exclusions_path: str | Path | None = None) -> AppConfig:
    """Load and validate the YAML configuration and exclusion list."""
    path = Path(config_path)
    data = _load_yaml(path)
    allowed = {"execution", "policy", "jetbrains", "active_directory", "safety", "reporting",
               "notifications", "exclusions_file", "log_level"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown top-level key(s): {', '.join(sorted(unknown))}")

    notif = data.get("notifications") or {}
    notifications = NotificationConfig(
        slack=_build(SlackConfig, notif.get("slack"), "notifications.slack"),
        email=_build(EmailConfig, notif.get("email"), "notifications.email"),
        include_product_breakdown=bool(notif.get("include_product_breakdown", True)),
    )

    if exclusions_path is None and data.get("exclusions_file"):
        # Relative paths are resolved against the working directory (the repository root in Jenkins).
        exclusions_path = Path(data["exclusions_file"])
        if not exclusions_path.exists():
            raise ConfigError(f"Exclusions file not found: {exclusions_path}")

    config = AppConfig(
        execution=_build(ExecutionConfig, data.get("execution"), "execution"),
        policy=_build(PolicyConfig, data.get("policy"), "policy"),
        jetbrains=_build(JetBrainsConfig, data.get("jetbrains"), "jetbrains"),
        active_directory=_build(ADConfig, data.get("active_directory"), "active_directory"),
        safety=_build(SafetyConfig, data.get("safety"), "safety"),
        reporting=_build(ReportingConfig, data.get("reporting"), "reporting"),
        notifications=notifications,
        exclusions=load_exclusions(Path(exclusions_path) if exclusions_path else None),
        log_level=str(data.get("log_level", "INFO")),
    )
    validate_config(config)
    return config


def apply_overrides(config: AppConfig, overrides: dict[str, Any]) -> AppConfig:
    """Apply manual-run parameter overrides (from Jenkins build parameters).

    Overrides may only make a run *safer* than the hard limits in the
    reviewed configuration file: MAX_REVOCATIONS is capped at
    ``safety.hard_max_revocations``.
    """
    if overrides.get("inactivity_months") is not None:
        config.policy.inactivity_months = int(overrides["inactivity_months"])
    if overrides.get("revoke_disabled_users") is not None:
        config.policy.revoke_disabled_users = bool(overrides["revoke_disabled_users"])
    if overrides.get("revoke_inactive_users") is not None:
        config.policy.revoke_inactive_users = bool(overrides["revoke_inactive_users"])
    if overrides.get("max_revocations") is not None:
        config.safety.max_revocations = int(overrides["max_revocations"])
    if overrides.get("max_revocation_percent") is not None:
        config.safety.max_revocation_percent = float(overrides["max_revocation_percent"])
    if overrides.get("log_level"):
        config.log_level = str(overrides["log_level"])
    validate_config(config)
    return config


def validate_config(config: AppConfig) -> None:
    """Validate configuration values. Raises :class:`ConfigError`."""
    errors: list[str] = []
    p, j, a, s = config.policy, config.jetbrains, config.active_directory, config.safety

    if config.execution.scheduled_mode not in ("dry-run", "production"):
        errors.append("execution.scheduled_mode must be 'dry-run' or 'production'")
    if config.execution.scheduled_mode == "production" and not config.execution.production_enabled:
        errors.append("execution.scheduled_mode is 'production' but execution.production_enabled is false")
    if config.execution.production_enabled and not (config.execution.approved_by and config.execution.approved_on):
        errors.append("execution.production_enabled requires execution.approved_by and execution.approved_on")
    if not 1 <= p.inactivity_months <= 60:
        errors.append("policy.inactivity_months must be between 1 and 60")
    if p.min_assignment_age_days < 30:
        errors.append("policy.min_assignment_age_days must be >= 30 (JetBrains API rule)")
    if not j.base_url.startswith("https://"):
        errors.append("jetbrains.base_url must use https://")
    if not 1 <= j.page_size <= 1000:
        errors.append("jetbrains.page_size must be between 1 and 1000")
    if j.max_retries < 0 or j.max_retries > 10:
        errors.append("jetbrains.max_retries must be between 0 and 10")
    if j.ca_bundle is not None and not isinstance(j.ca_bundle, str):
        errors.append("jetbrains.ca_bundle must be a file path or null (TLS verification cannot be disabled)")
    if a.port not in (636, 3269):
        errors.append("active_directory.port must be an LDAPS port (636 or 3269); plain LDAP is not allowed")
    if a.search_scope.upper() not in ("SUBTREE", "LEVEL", "BASE"):
        errors.append("active_directory.search_scope must be SUBTREE, LEVEL or BASE")
    for name, value in (("active_directory.server", a.server), ("active_directory.base_dn", a.base_dn),
                        ("active_directory.domain", a.domain)):
        if not value:
            errors.append(f"{name} is required")
    if s.max_revocations < 0 or s.max_revocations > s.hard_max_revocations:
        errors.append(f"safety.max_revocations must be between 0 and safety.hard_max_revocations ({s.hard_max_revocations})")
    if not 0 <= s.max_revocation_percent <= 100:
        errors.append("safety.max_revocation_percent must be between 0 and 100")
    if not 0 <= s.max_ad_lookup_failure_percent <= 100:
        errors.append("safety.max_ad_lookup_failure_percent must be between 0 and 100")
    if s.max_consecutive_revocation_failures < 1:
        errors.append("safety.max_consecutive_revocation_failures must be >= 1")
    if config.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        errors.append("log_level must be DEBUG, INFO, WARNING or ERROR")
    if config.notifications.email.enabled and not (config.notifications.email.smtp_host and config.notifications.email.recipients):
        errors.append("notifications.email requires smtp_host and recipients when enabled")
    if errors:
        raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(errors))


def validate_secrets(secrets: Secrets, need_jetbrains: bool = True, need_ad: bool = True) -> None:
    """Ensure the secrets required for a stage are present (values never printed)."""
    missing = []
    if need_jetbrains:
        if not secrets.jetbrains_api_token:
            missing.append(ENV_JETBRAINS_TOKEN)
        if not secrets.jetbrains_customer_code:
            missing.append(ENV_JETBRAINS_CUSTOMER_CODE)
    if need_ad:
        if not secrets.ad_bind_user:
            missing.append(ENV_AD_BIND_USER)
        if not secrets.ad_bind_password:
            missing.append(ENV_AD_BIND_PASSWORD)
    if missing:
        raise ConfigError("Missing required secret environment variable(s): " + ", ".join(missing))
