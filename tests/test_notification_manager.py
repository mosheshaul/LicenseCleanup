"""Notification tests (Slack mocked, no email sent)."""

from __future__ import annotations

import json

import responses

from license_cleanup.config_manager import NotificationConfig, Secrets, SlackConfig
from license_cleanup.notification_manager import build_message, notify

SUMMARY = {
    "execution_id": "E1", "trigger": "scheduled", "mode": "PRODUCTION", "started_at": "2026-12-01T02:10:00Z",
    "overall_status": "SUCCESS",
    "totals": {"licenses_discovered": 120, "assigned_licenses": 100, "disabled_users": 3,
               "inactive_license_assignments": 4, "successfully_revoked": 7, "failed_revocations": 0,
               "manual_review": 5, "eligible_for_revocation": 7, "revocations_verified": 7},
    "revoked_by_product_and_reason": {"PyCharm Professional": {"PRODUCT_INACTIVE": 4}},
    "safety": {"ok": True, "violations": []},
}
WEBHOOK = "https://hooks.slack.com/services/TFAKE/BFAKE/fakefakefake"


def test_message_contains_required_fields_and_no_personal_data() -> None:
    subject, body = build_message(SUMMARY, "https://jenkins.example.test/job/x/5/", "https://jenkins.example.test/job/x/5/artifact/")
    for text in ("PRODUCTION", "Licenses analyzed: 120", "Disabled users identified: 3", "Inactive licenses identified: 4",
                 "Licenses revoked: 7", "Failed operations: 0", "manual review: 5", "PyCharm Professional",
                 "jenkins.example.test/job/x/5/", "artifact"):
        assert text in body or text in subject
    assert "@" not in body


@responses.activate
def test_slack_notification_sent() -> None:
    responses.post(WEBHOOK, status=200)
    errors = notify(NotificationConfig(slack=SlackConfig(enabled=True)), Secrets(slack_webhook_url=WEBHOOK), SUMMARY)
    assert errors == []
    assert "Licenses revoked: 7" in json.loads(responses.calls[0].request.body)["text"]


@responses.activate
def test_slack_failure_is_reported_not_raised() -> None:
    responses.post(WEBHOOK, status=500)
    errors = notify(NotificationConfig(slack=SlackConfig(enabled=True)), Secrets(slack_webhook_url=WEBHOOK), SUMMARY)
    assert errors and WEBHOOK not in errors[0]


def test_missing_webhook_is_reported() -> None:
    errors = notify(NotificationConfig(slack=SlackConfig(enabled=True)), Secrets(), SUMMARY)
    assert errors == ["Slack enabled but SLACK_WEBHOOK_URL is not set"]


def test_smtp_credentials_never_sent_without_starttls(monkeypatch) -> None:
    from license_cleanup.config_manager import EmailConfig

    logins: list[str] = []

    class FakeSMTP:
        def __init__(self, *a, **k) -> None: ...
        def __enter__(self): return self
        def __exit__(self, *a) -> None: ...
        def starttls(self, **k) -> None: ...
        def login(self, user, password) -> None: logins.append(user)
        def send_message(self, msg) -> None: ...

    monkeypatch.setattr("license_cleanup.notification_manager.smtplib.SMTP", FakeSMTP)
    cfg = NotificationConfig(email=EmailConfig(enabled=True, smtp_host="smtp.example.test", use_starttls=False,
                                               sender="a@example.test", recipients=["b@example.test"]))
    errors = notify(cfg, Secrets(smtp_user="u", smtp_password="fake-pass"), SUMMARY)
    assert logins == [] and errors and "RuntimeError" in errors[0]


@responses.activate
def test_slack_redirect_is_not_followed() -> None:
    responses.post(WEBHOOK, status=302, headers={"Location": "https://attacker.example.test/"})
    errors = notify(NotificationConfig(slack=SlackConfig(enabled=True)), Secrets(slack_webhook_url=WEBHOOK), SUMMARY)
    assert errors and len(responses.calls) == 1
