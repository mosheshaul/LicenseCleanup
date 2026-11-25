# Security

## Threat model summary

| Risk | Control |
|---|---|
| Secret leakage via Git | Secrets only in Jenkins Credentials; YAML loader rejects secret-like keys; `.gitignore` excludes env/key files |
| Secret leakage via logs/output | Credentials Binding masking; secrets passed as env vars (not argv); single-quoted `sh` blocks; redacting log filter for registered secrets and credential patterns; HTTP headers never logged; `repr=False` on secret fields |
| Secret leakage via reports | Reports contain no credentials; summary/notifications contain aggregates only |
| Man-in-the-middle | HTTPS only for JetBrains (`verify` is always on, optional corporate CA bundle); LDAPS only (port 636/3269) with `CERT_REQUIRED`, hostname check and TLS 1.2+ |
| LDAP injection via email values | RFC 4515 escaping (`escape_filter_chars`) on every filter value |
| CSV/spreadsheet formula injection | Cells starting with `= + - @ | %`, tab or CR are prefixed with `'` |
| Wrong revocation from bad data | Fail-closed checks: inventory completeness, schema validation, AD failure gates, manual review for ambiguous identity or missing usage, revalidation before every revocation |
| Mass revocation | Count and percentage limits, hard cap that parameters cannot exceed, abort after consecutive failures |
| Accidental production run | Dry run by default; production requires `production_enabled: true` plus approval metadata in a reviewed commit; scheduled runs ignore parameters |
| Over-privileged accounts | Read-only AD account (not Domain Admin); JetBrains token from a dedicated account with only the needed permission |
| Concurrency/races | `disableConcurrentBuilds`; per-run de-duplication; revalidation right before each write |
| Personal data exposure | Report files written with mode 600; workspace state wiped after each build; job read access restricted; Slack/email carry no names or emails |
| Supply chain | Pinned dependencies; `pip-audit` on every build |

## Credential handling

- Never commit tokens or passwords. If one is committed: rotate it immediately, then purge it from history.
- Rotation procedures: [JetBrains token](docs/jetbrains_setup.md#token-rotation), [AD password](docs/active_directory_setup.md#password-rotation). Slack webhook: regenerate in Slack, update `slack-webhook-url`.
- JetBrains tokens do not expire, so schedule rotation (at least yearly) and rotate when admins leave.

## Data handled

Assignee emails and names (from JetBrains), `sAMAccountName`, `userPrincipalName` and enabled/disabled state (from AD), and last-seen dates. These are needed for the audit trail. Keep the archived reports only as long as your retention policy requires (see `buildDiscarder` in the Jenkinsfile).

## Hardening options

- Use a folder-scoped credentials store, or an external secrets manager (HashiCorp Vault, Azure Key Vault, CyberArk) through its Jenkins plugin that exposes the same credential IDs.
- Install dependencies from an internal mirror and add `--require-hashes` with a hash-locked requirements file.
- Run the agent in an isolated network segment that can reach only the hosts listed in [jenkins_setup.md](docs/jenkins_setup.md#agent-requirements).

## Reporting a vulnerability

Contact the IT Security team privately (placeholder: security@example.com). Do not open a public issue.
