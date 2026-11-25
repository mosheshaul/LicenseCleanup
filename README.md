# JetBrains License Cleanup

Monthly Jenkins automation that reclaims JetBrains licenses from:

1. users whose **Active Directory account is disabled**, and
2. enabled users who have **not used a licensed product for more than 6 calendar months**,

using only the **official JetBrains Account REST API** and **read-only LDAPS** queries to Active Directory.
It is dry-run by default, guarded by mass-revocation limits, and produces a full CSV audit trail and JSON summary for every run.

> **Read [Known limitations](#known-limitations) before enabling production mode.** In particular, JetBrains exposes usage as a per-license `lastSeen.lastSeenDate` and refuses to revoke licenses assigned less than 30 days ago.

## Contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Quick start (local dry run)](#quick-start-local-dry-run)
- [Running the tests](#running-the-tests)
- [Configuration](#configuration)
- [Exclusions](#exclusions)
- [Enabling production mode safely](#enabling-production-mode-safely)
- [Reports](#reports)
- [Restoring a mistakenly revoked license](#restoring-a-mistakenly-revoked-license)
- [Known limitations](#known-limitations)
- Detailed guides: [deployment handover](docs/deployment_handover.md), [architecture](docs/architecture.md), [Jenkins](docs/jenkins_setup.md), [JetBrains](docs/jetbrains_setup.md), [Active Directory](docs/active_directory_setup.md), [troubleshooting](docs/troubleshooting.md), [security](SECURITY.md)

## How it works

1. Pull the complete license inventory from `GET /customer/licenses` (assigned **and** unassigned, every page). Abort if the number collected does not match `X-Total-Count`.
2. Look up every assignee email in AD over LDAPS (`mail`, then `userPrincipalName`, then `proxyAddresses`, then configured domain aliases, then `sAMAccountName` as a weak fallback).
3. Evaluate each license **independently**:

| Order | Condition | Action |
|---|---|---|
| - | License unassigned / assigned to a license server or key | Skip |
| 1 | User, license, product or team is excluded | Keep |
| 2 | AD lookup failed | Do not revoke |
| 2 | Not found in AD / several AD matches / contractor domain / weak (sAMAccountName-only) match | Manual review |
| 3 | AD account disabled (`userAccountControl` & `ACCOUNTDISABLE`) | **Revoke** |
| 4 | Enabled, offline activation code generated | Manual review |
| 4 | Enabled, no usage date | Manual review |
| 4 | Enabled, usage date predates the current assignment | Manual review |
| 4 | Enabled, last usage **strictly before** now minus N calendar months | **Revoke** |
| 4 | Enabled, used within N months | Keep |
| - | Would revoke but assigned < 30 days ago (JetBrains rule) | Manual review (deferred) |

4. Run safety gates: inventory completeness, AD failure rate, max revocations, max % of assigned licenses. **Any violation blocks every revocation in the run.**
5. In production mode only: for each candidate, re-read the license and (for disabled users) re-query AD; revoke **by license ID only**; re-read the license to verify; never blindly retry an uncertain result.
6. Write the CSV audit report and JSON summary, archive them in Jenkins, and send an aggregate-only Slack/email summary.

## Repository layout

```
jetbrains-license-cleanup/
├── Jenkinsfile                  # Declarative pipeline (18 stages, monthly cron + manual)
├── README.md  SECURITY.md  CHANGELOG.md
├── .gitignore
├── requirements.txt             # pinned runtime deps
├── requirements-dev.txt         # pinned test/scan deps (pytest, responses, pip-audit)
├── pyproject.toml
├── config/
│   ├── config.example.yaml      # documented template
│   ├── config.yaml              # the reviewed, approved configuration (no secrets)
│   ├── exclusions.example.yaml
│   └── exclusions.yaml
├── src/license_cleanup/
│   ├── main.py                  # CLI: one sub-command per pipeline stage, plus `run`
│   ├── models.py                # dataclasses shared across modules (added)
│   ├── jetbrains_client.py      # JetBrains Account API (documented endpoints only)
│   ├── ad_client.py             # read-only LDAPS lookups
│   ├── license_manager.py       # business rules + guarded revocation
│   ├── safety_checks.py         # dry-run resolution and safety gates
│   ├── config_manager.py        # YAML + env secrets, validation
│   ├── report_generator.py      # CSV (formula-injection safe) + JSON summary
│   ├── notification_manager.py  # Slack webhook / SMTP, aggregates only
│   └── logger.py                # logging with secret redaction
├── tests/                       # 100+ pytest tests, all mocked
├── docs/
├── reports/   (git-ignored output)
└── logs/      (git-ignored output)
```

## Quick start (local dry run)

Requires Python 3.10+ and network access to `account.jetbrains.com` and a domain controller on 636/tcp.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt && pip install --no-deps -e .

cp config/config.example.yaml config/config.yaml        # then edit the placeholders
cp config/exclusions.example.yaml config/exclusions.yaml

# Secrets only via environment variables (prompted, so nothing lands in shell history):
read -rs JETBRAINS_API_TOKEN && export JETBRAINS_API_TOKEN
read -rs JETBRAINS_CUSTOMER_CODE && export JETBRAINS_CUSTOMER_CODE
read -r  AD_BIND_USER && export AD_BIND_USER            # e.g. svc-jb-ldap@corp.example.com
read -rs AD_BIND_PASSWORD && export AD_BIND_PASSWORD

python -m license_cleanup run --config config/config.yaml   # dry run is the default
ls reports/*/
```

Individual stages can be run the same way (`init`, `validate-config`, `check-jetbrains`, `check-ad`, `inventory`, `match-ad`, `analyze`, `plan`, `safety-check`, `revoke`, `verify`, `report`, `notify`); they share state in `.state/`.

Exit codes: `0` success, `1` partial failure or safety gate blocked (Jenkins UNSTABLE), `2` critical failure (Jenkins FAILURE).

## Running the tests

```bash
. .venv/bin/activate
python -m pytest -q                     # unit + integration tests, all external systems mocked
python -m pytest --cov --cov-report=term-missing
pip-audit -r requirements.txt           # dependency vulnerability scan
```

The tests never contact JetBrains or AD; every identity, token and host in them is fictional.

## Configuration

All non-sensitive settings live in `config/config.yaml` (fully commented in `config.example.yaml`). The loader **rejects** keys that look like secrets, unknown keys, `http://` API URLs and non-LDAPS ports.

Secrets are read only from environment variables, which Jenkins injects per stage:

| Variable | Jenkins credential ID | Type |
|---|---|---|
| `JETBRAINS_API_TOKEN` | `jetbrains-api-token` | Secret text |
| `JETBRAINS_CUSTOMER_CODE` | `jetbrains-customer-code` | Secret text |
| `AD_BIND_USER` / `AD_BIND_PASSWORD` | `ad-service-account` | Username with password |
| `SLACK_WEBHOOK_URL` (optional) | `slack-webhook-url` | Secret text |
| `SMTP_USER` / `SMTP_PASSWORD` (optional) | `smtp-relay-account` | Username with password |

Manual Jenkins runs can override `INACTIVITY_MONTHS`, `REVOKE_DISABLED_USERS`, `REVOKE_INACTIVE_USERS`, `MAX_REVOCATIONS` (never above `safety.hard_max_revocations`), `MAX_REVOCATION_PERCENT` and `LOG_LEVEL`. **Scheduled runs ignore all parameters.**

## Exclusions

Edit `config/exclusions.yaml` (reviewed via pull request; no code change needed):

```yaml
emails: [cto@example.com]
email_patterns: ["svc-*@example.com"]
service_accounts: [build-agent@example.com]
protected_users: [on-leave.employee@example.com]
license_ids: ["ABC1234567"]
product_codes: ["DPN"]     # whole products
team_ids: [12345]          # JetBrains teams
team_names: ["Research"]
```

Excluded licenses are reported as `KEEP` with an `ExclusionStatus` explaining why.

## Enabling production mode safely

1. Run at least two monthly **dry runs**; have license owners review `ProposedAction=REVOKE` and `MANUAL_REVIEW` rows.
2. Tune `exclusions.yaml` and the safety limits until the plan contains no surprises.
3. In a reviewed pull request set:
   ```yaml
   execution:
     production_enabled: true
     approved_by: "IT Asset Management - CHG0012345"
     approved_on: "2027-01-15"
   ```
4. Do one **manual** production run with `DRY_RUN` unchecked and a small `MAX_REVOCATIONS` (e.g. 5). Verify the revoked licenses in the JetBrains console.
5. In another reviewed pull request set `execution.scheduled_mode: production`. From then on the monthly run revokes automatically within the safety limits, without monthly approval.

To stop revocations immediately, set `production_enabled: false` (or disable the Jenkins job).

## Reports

Each run writes to `reports/<execution-id>/` (archived by Jenkins; file mode 600):

- `license_audit_<timestamp>.csv`: one row per license with all audit columns (`Timestamp`, `ExecutionID`, ..., `VerificationStatus`, `ErrorMessage`). Cells are protected against spreadsheet formula injection.
- `proposed_revocation_plan.csv`: only the licenses proposed for revocation.
- `execution_summary_<timestamp>.json`: totals, revocations by product and reason, safety results, duration and overall status (`SUCCESS`, `PARTIAL_FAILURE`, `SAFETY_BLOCKED`, `CRITICAL_FAILURE`). Contains no personal data.

How to read the key columns:

| Column | Meaning |
|---|---|
| `ProposedAction` | What the rules decided: `REVOKE`, `KEEP`, `MANUAL_REVIEW`, `SKIP`, `DO_NOT_REVOKE` |
| `ActualAction` / `Result` | What happened: `DRY_RUN_NO_CHANGE`, `REVOKED`, `FAILED`, `UNCERTAIN`, `SKIPPED_AFTER_REVALIDATION`, `ABORTED` |
| `VerificationStatus` | `VERIFIED` when a re-read of the license confirmed it is no longer assigned to the user |
| `LastProductUsage` / `UsageDataSource` | `lastSeen.lastSeenDate` from the JetBrains API, or `UNAVAILABLE` |
| `ErrorMessage` | For non-revoked rows, the reason (e.g. "User not found in Active Directory") |

**Cost:** the API exposes no prices, so the summary reports *reclaimed license capacity*. If you add administrator-provided prices under `reporting.pricing`, it also shows an *estimated value of reclaimed capacity*, which is not the same as a subscription cost reduction: the bill only goes down if seats are reduced at renewal.

## Restoring a mistakenly revoked license

1. Find the row in the audit CSV (`LicenseID`, `EmailAddress`, `ProductName`).
2. In the JetBrains Account console go to **Licenses**, find an available license for the product (the revoked one returns to the pool), click **Assign**, and enter the user's email and name. Alternatively use `POST /customer/licenses/assign` with the same API token.
3. The user restarts the IDE or re-logs into their JetBrains Account in the IDE.
4. Add the user or license to `config/exclusions.yaml` if the revocation was a policy gap.

Note: a license assigned less than 30 days ago cannot be revoked again via the API until 30 days pass.

## Known limitations

- **Usage data is per license, not per user/IDE session.** The only official usage signal is `lastSeen.lastSeenDate` on each license. JetBrains does not define it precisely in the OpenAPI spec; it is the date JetBrains last saw the license in use. It is used as-is and labelled as such in reports. Website logins and assignment dates are never used as a substitute.
- **Offline activation codes** (`lastSeen.isOfflineCodeGenerated`) stop the IDE from reporting usage, so such licenses go to manual review.
- **Usage before reassignment**: if `lastSeenDate` is older than `lastAssignmentDate`, the usage may belong to a previous holder, so the license goes to manual review. This includes licenses assigned >6 months ago and never used since; review them manually.
- **Bundles**: an All Products Pack is one license with one `lastSeenDate`; the API does not say which IDE was used. Recent use of any covered IDE keeps the bundle, which matches the requirement.
- **30-day rule**: JetBrains rejects revocation of licenses assigned less than 30 days ago (`RECENTLY_ASSIGNED_LICENSE_IS_NOT_AVAILABLE_FOR_REVOKE`). Such candidates are deferred to manual review.
- **Rate limits are not documented** by JetBrains. The client honours `Retry-After` on HTTP 429 and backs off exponentially.
- **License Vault / IDE Services** have a separate API (`https://<company>.fls.jetbrains.com`, Bearer token) whose endpoint specification is only visible to License Vault administrators. It is **not** implemented, because its endpoints could not be verified. Licenses served by a license server appear in the Account API with assignee type `SERVER` and are skipped.
- **Percentage limit on small pools**: `max_revocation_percent` uses a floor, so with 10% and fewer than 10 assigned licenses no revocation is allowed. Raise the percentage for small organizations.
- The Jenkinsfile was written against standard plugins but has not been executed on your Jenkins controller; run it once in dry-run mode to confirm the agent label, plugins and credential IDs.
