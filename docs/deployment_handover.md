# Deployment handover

## What was built

A Jenkins-driven Python tool that, once a month (and on demand):

1. Reads the full JetBrains license inventory through the official **JetBrains Account API**.
2. Checks every licensed user in **Active Directory over LDAPS** (read-only).
3. Revokes licenses of **disabled** AD users and, for enabled users, each **individually assigned product license unused for more than 6 calendar months** (based on the license's official `lastSeen.lastSeenDate`).
4. Sends ambiguous cases (user not in AD, multiple matches, missing or unattributable usage, too recently assigned) to **manual review** instead of revoking them.
5. Produces an audit CSV, revocation plan CSV and JSON summary, archives them in Jenkins and sends an aggregate Slack/email summary.

Dry run is the default. Production requires an approved configuration change.

## Test results

- 105 pytest tests passing (unit and integration; JetBrains API mocked with `responses`, AD with an in-memory LDAP double). Line+branch coverage 86%.
- `pip-audit -r requirements.txt`: no known vulnerabilities (25 Nov 2026).
- `bandit -r src`: no findings.
- Not tested: a real Jenkins controller, a real domain controller, the real JetBrains API (no production access by design).

## Values you still need to provide

| Where | Value |
|---|---|
| Jenkins credential `jetbrains-api-token` | JetBrains Account API organization (or team) token |
| Jenkins credential `jetbrains-customer-code` | JetBrains customer code |
| Jenkins credential `ad-service-account` | Read-only AD service account UPN + password |
| Jenkins credential `slack-webhook-url` (optional) | Private-channel incoming webhook |
| Jenkins credential `smtp-relay-account` (optional) | SMTP auth, if your relay needs it |
| `config.yaml` `active_directory.domain`, `server`, `base_dn`, `ca_certs_file` | Your AD details and the CA that signed the DC certificates |
| `config.yaml` `active_directory.external_domains`, `email_domain_aliases` | Contractor domains, old email domains |
| `config.yaml` `jetbrains.team_ids` | Only if you use team tokens or want to limit scope |
| `config.yaml` `jetbrains.ca_bundle` / Jenkinsfile proxy vars | Only behind a TLS-inspecting proxy |
| `config.yaml` `safety.*` | Limits suited to your license count |
| `config.yaml` `notifications.*` | Channels and recipients |
| `config.yaml` `reporting.pricing` (optional) | Your per-license prices, if you want value estimates |
| `config/exclusions.yaml` | Protected users, service accounts, licenses, products, teams |
| Jenkinsfile `CRON_TZ`, `AGENT_LABEL` | Your timezone and agent label |
| `config.yaml` `execution.approved_by/approved_on` | Only when enabling production |

## Step-by-step deployment

1. Create a Git repository (e.g. `jetbrains-license-cleanup`) and push this code (`git clone jetbrains-license-cleanup.bundle` gives you the history).
2. Install the Jenkins plugins listed in [jenkins_setup.md](jenkins_setup.md#required-plugins); prepare a Linux agent with Python 3.10+, the corporate CA, and network access (443 to JetBrains/PyPI, 636 to DCs).
3. Create the AD service account ([active_directory_setup.md](active_directory_setup.md)) and verify LDAPS from the agent with `openssl s_client`.
4. Enable the JetBrains Account API and generate the token ([jetbrains_setup.md](jetbrains_setup.md)).
5. Add the Jenkins credentials with the exact IDs above (folder-scoped).
6. Fill in `config/config.yaml` and `config/exclusions.yaml`, commit via pull request.
7. Create the Pipeline job from SCM, restrict its permissions, and run **Build Now** once (dry run).
8. Review the archived audit CSV with the license owners. Repeat for at least one monthly cycle.
9. Enable production via reviewed PR (`production_enabled`, `approved_by`, `approved_on`), do one manual production run with a small `MAX_REVOCATIONS`, verify in the JetBrains console.
10. Set `execution.scheduled_mode: production` via reviewed PR.

## Production-readiness checklist

- [ ] Jenkinsfile runs end to end in dry-run mode on your controller
- [ ] All 18 stages visible; tests and `pip-audit` pass on the agent
- [ ] AD service account is not privileged, has no interactive logon, LDAPS certificate validates
- [ ] JetBrains token created from a dedicated MFA-protected account with the minimum permission
- [ ] Credentials folder-scoped; job read access limited to license administrators
- [ ] Exclusions reviewed (executives, service/build accounts, people on leave, shared licenses)
- [ ] At least one full dry-run report reviewed and signed off by license owners
- [ ] Safety thresholds agreed (`max_revocations`, `hard_max_revocations`, `max_revocation_percent`)
- [ ] Notification channel is private / distribution list is restricted
- [ ] Report retention matches your data-protection policy
- [ ] Restore procedure (README) known to the service desk
- [ ] Token and password rotation dates scheduled
- [ ] `production_enabled` approval recorded (change ticket) before the first production run
- [ ] First production run done manually with a low `MAX_REVOCATIONS` and verified
