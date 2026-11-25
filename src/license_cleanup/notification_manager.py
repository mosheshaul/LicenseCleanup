"""Execution summary notifications (Slack incoming webhook and/or SMTP email).

Notifications carry aggregate numbers only: no names, emails or license
ids, so they are safe for shared channels and distribution lists. Detailed
per-user data stays in the archived Jenkins reports, protected by Jenkins
access control.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import requests

from .config_manager import NotificationConfig, Secrets

log = logging.getLogger(__name__)


def build_message(summary: dict[str, Any], build_url: str = "", report_url: str = "") -> tuple[str, str]:
    """Return ``(subject, body)`` for the execution summary."""
    t = summary.get("totals", {})
    mode = summary.get("mode", "UNKNOWN")
    status = summary.get("overall_status", "UNKNOWN")
    subject = f"[JetBrains license cleanup] {status} - {mode} - {summary.get('started_at', '')[:10]}"
    lines = [
        f"Execution date: {summary.get('started_at', '')}",
        f"Execution mode: {mode} (trigger: {summary.get('trigger', '')})",
        f"Overall status: {status}",
        f"Licenses analyzed: {t.get('licenses_discovered', 0)} (assigned: {t.get('assigned_licenses', 0)})",
        f"Disabled users identified: {t.get('disabled_users', 0)}",
        f"Inactive licenses identified: {t.get('inactive_license_assignments', 0)}",
        f"Eligible for revocation: {t.get('eligible_for_revocation', 0)}",
        f"Licenses revoked: {t.get('successfully_revoked', 0)} (verified: {t.get('revocations_verified', 0)})",
        f"Failed operations: {t.get('failed_revocations', 0)}",
        f"Licenses requiring manual review: {t.get('manual_review', 0)}",
    ]
    breakdown = summary.get("revoked_by_product_and_reason") or summary.get("would_revoke_by_product_and_reason") or {}
    if breakdown:
        label = "Revoked" if mode == "PRODUCTION" else "Would revoke"
        lines.append(f"{label} by product:")
        for product, reasons in breakdown.items():
            parts = ", ".join(f"{r or 'n/a'}: {n}" for r, n in reasons.items())
            lines.append(f"  - {product}: {parts}")
    violations = (summary.get("safety") or {}).get("violations") or []
    if violations:
        lines.append("Safety gate blocked revocations:")
        lines += [f"  - {v}" for v in violations]
    for err in summary.get("errors") or []:
        lines.append(f"Error: {err}")
    if build_url:
        lines.append(f"Jenkins build: {build_url}")
    if report_url:
        lines.append(f"Reports: {report_url}")
    return subject, "\n".join(lines)


def send_slack(webhook_url: str, subject: str, body: str, timeout: float = 15.0) -> None:
    if not webhook_url.startswith("https://"):
        raise ValueError("Slack webhook URL must use HTTPS")
    response = requests.post(webhook_url, json={"text": f"*{subject}*\n```{body}```"}, timeout=timeout,
                             allow_redirects=False)
    if response.status_code >= 300:
        raise RuntimeError(f"Slack webhook returned HTTP {response.status_code}")


def send_email(cfg: NotificationConfig, secrets: Secrets, subject: str, body: str) -> None:
    email_cfg = cfg.email
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_cfg.sender
    msg["To"] = ", ".join(email_cfg.recipients)
    msg.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=email_cfg.timeout_seconds) as smtp:
        if email_cfg.use_starttls:
            smtp.starttls(context=context)
        if secrets.smtp_user and secrets.smtp_password:
            if not email_cfg.use_starttls:
                raise RuntimeError("Refusing to send SMTP credentials over an unencrypted connection (use_starttls is false)")
            smtp.login(secrets.smtp_user, secrets.smtp_password)
        smtp.send_message(msg)


def notify(cfg: NotificationConfig, secrets: Secrets, summary: dict[str, Any], build_url: str = "",
           report_url: str = "") -> list[str]:
    """Send notifications; returns a list of delivery errors (never raises)."""
    subject, body = build_message(summary, build_url, report_url)
    errors: list[str] = []
    if cfg.slack.enabled:
        if not secrets.slack_webhook_url:
            errors.append("Slack enabled but SLACK_WEBHOOK_URL is not set")
        else:
            try:
                send_slack(secrets.slack_webhook_url, subject, body)
                log.info("Slack notification sent")
            except Exception as exc:  # notification failures must not hide run results
                errors.append(f"Slack notification failed: {type(exc).__name__}")
    if cfg.email.enabled:
        try:
            send_email(cfg, secrets, subject, body)
            log.info("Email notification sent to %d recipient(s)", len(cfg.email.recipients))
        except Exception as exc:
            errors.append(f"Email notification failed: {type(exc).__name__}")
    if not cfg.slack.enabled and not cfg.email.enabled:
        log.info("No notification channel enabled; summary:\n%s", body)
    for err in errors:
        log.warning(err)
    return errors
