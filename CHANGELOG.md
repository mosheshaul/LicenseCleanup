# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-25

### Added
- JetBrains Account API client (documented endpoints only): products, paged license inventory with completeness checks, single-license revocation by ID, verification by re-read, 429/5xx handling with bounded exponential backoff.
- Read-only LDAPS Active Directory client with mail / UPN / proxyAddresses / domain alias / weak sAMAccountName matching, LDAP filter escaping and `ACCOUNTDISABLE` detection.
- Business rules: exclusions, disabled users, per-license inactivity with calendar-month thresholds, manual review for ambiguous identity or missing usage, JetBrains 30-day rule.
- Safety gates: dry run by default, approved production switch, scheduled runs ignore parameters, max revocations, max percentage, AD failure rate, inventory completeness, consecutive-failure abort, revalidation before each revocation.
- CSV audit report (formula-injection safe), revocation plan CSV and JSON execution summary.
- Slack webhook and SMTP notifications with aggregate data only.
- Declarative Jenkinsfile with 18 stages, monthly cron, per-stage credential binding and `pip-audit`.
- Pytest suite with mocked JetBrains API and AD.
- Documentation: architecture, Jenkins, JetBrains, AD, troubleshooting, security.
