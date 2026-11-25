"""Configuration validation and secret redaction tests."""

from __future__ import annotations

import logging

import pytest

from license_cleanup.config_manager import ConfigError, Secrets, apply_overrides, load_config, validate_secrets
from license_cleanup.logger import REDACTED, SecretRedactingFilter, redact, register_secret

BASE = """
active_directory:
  domain: corp.example.test
  server: dc01.corp.example.test
  base_dn: "DC=corp,DC=example,DC=test"
"""


def write(tmp_path, text):
    path = tmp_path / "c.yaml"
    path.write_text(text)
    return path


def test_example_config_is_valid() -> None:
    config = load_config("config/config.example.yaml", "config/exclusions.example.yaml")
    assert config.execution.production_enabled is False
    assert config.policy.inactivity_months == 6


def test_secrets_in_yaml_are_rejected(tmp_path) -> None:
    with pytest.raises(ConfigError, match="secret"):
        load_config(write(tmp_path, BASE + "jetbrains:\n  api_token: abc123\n"))


def test_plain_ldap_port_rejected(tmp_path) -> None:
    with pytest.raises(ConfigError, match="LDAPS"):
        load_config(write(tmp_path, BASE + "  port: 389\n"))


def test_http_base_url_rejected(tmp_path) -> None:
    with pytest.raises(ConfigError, match="https"):
        load_config(write(tmp_path, BASE + "jetbrains:\n  base_url: http://x.test\n"))


def test_production_requires_approval_record(tmp_path) -> None:
    with pytest.raises(ConfigError, match="approved_by"):
        load_config(write(tmp_path, BASE + "execution:\n  production_enabled: true\n"))


def test_unknown_keys_rejected(tmp_path) -> None:
    with pytest.raises(ConfigError, match="Unknown"):
        load_config(write(tmp_path, BASE + "policy:\n  inactivty_months: 3\n"))


def test_overrides_cannot_exceed_hard_cap(tmp_path) -> None:
    config = load_config(write(tmp_path, BASE))
    with pytest.raises(ConfigError):
        apply_overrides(config, {"max_revocations": config.safety.hard_max_revocations + 1})


def test_missing_secrets_named_not_printed() -> None:
    with pytest.raises(ConfigError) as exc:
        validate_secrets(Secrets(jetbrains_api_token="fake-tok"), need_ad=False)
    assert "JETBRAINS_CUSTOMER_CODE" in str(exc.value) and "fake-tok" not in str(exc.value)


def test_secrets_repr_hides_values() -> None:
    assert "fake-tok-value" not in repr(Secrets(jetbrains_api_token="fake-tok-value"))


def test_redaction_of_registered_secrets_and_patterns() -> None:
    register_secret("super-secret-value-123")
    assert "super-secret-value-123" not in redact("error with super-secret-value-123 inside")
    assert REDACTED in redact("headers: {'X-Api-Key': 'abc'}")
    assert REDACTED in redact("password=hunter2")
    assert REDACTED in redact("https://hooks.slack.com/services/T000/B000/XXXX")


def test_log_filter_redacts_records() -> None:
    register_secret("another-fake-secret")
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "value %s", ("another-fake-secret",), None)
    SecretRedactingFilter().filter(record)
    assert "another-fake-secret" not in record.getMessage()


def test_overrides_cannot_lower_inactivity_or_raise_percent(tmp_path) -> None:
    config = load_config(write(tmp_path, BASE))
    with pytest.raises(ConfigError, match="INACTIVITY_MONTHS"):
        apply_overrides(config, {"inactivity_months": config.policy.inactivity_months - 1})
    with pytest.raises(ConfigError, match="MAX_REVOCATION_PERCENT"):
        apply_overrides(config, {"max_revocation_percent": config.safety.max_revocation_percent + 1})
    apply_overrides(config, {"inactivity_months": config.policy.inactivity_months + 6, "max_revocation_percent": 1})
    assert config.safety.max_revocation_percent == 1


def test_blank_jenkins_parameters_mean_use_config() -> None:
    from license_cleanup.main import build_parser

    args = build_parser().parse_args(["init", "--inactivity-months", "", "--max-revocations", " ",
                                      "--max-revocation-percent", ""])
    assert args.inactivity_months is None and args.max_revocations is None and args.max_revocation_percent is None
