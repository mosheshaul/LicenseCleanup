# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-11-25

### Security
- JetBrains API and Slack calls no longer follow HTTP redirects, so the API key header cannot be forwarded to another host.
- SMTP login is refused unless STARTTLS is enabled.
- Licenses without a `lastAssignmentDate` are no longer revoked for inactivity (last-seen date could belong to a previous assignee); they go to manual review.
- Manual Jenkins parameters can no longer lower `INACTIVITY_MONTHS` or raise `MAX_REVOCATION_PERCENT` beyond the reviewed config; blank parameters use the config values.
- Runtime dependencies are hash-locked (including transitive packages) and installed with `--require-hashes`; test tools run in a separate virtualenv; the package runs from source instead of an editable install.
- CSV formula-injection protection also covers values with leading whitespace.
- Dependabot configuration for pip and GitHub security updates.

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
