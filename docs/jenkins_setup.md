# Jenkins setup

## Required plugins

| Plugin | Used for |
|---|---|
| Pipeline (workflow-aggregator) | Declarative pipeline |
| Git | `checkout scm` |
| Credentials + Credentials Binding | `withCredentials` (`string`, `usernamePassword`) |
| Pipeline Utility Steps | `readJSON` |
| Timestamper | `timestamps()` |
| Workspace Cleanup | `cleanWs` |
| JUnit | test results |
| Mask Passwords (optional) | extra console masking |

Credentials Binding already masks bound secrets in console output.

## Agent requirements

- Linux agent labelled `linux && python3` (change `AGENT_LABEL` in the Jenkinsfile), Python 3.10+ with `venv`.
- Outbound: `account.jetbrains.com:443`, `pypi.org`/`files.pythonhosted.org:443` (or your internal PyPI mirror) for dependencies, the OSV/PyPI vulnerability database for `pip-audit`, the domain controllers on `636/tcp`, and optionally Slack (`hooks.slack.com:443`) or your SMTP relay (`587/tcp`).
- Corporate root CA installed and, if needed, the proxy variables in the Jenkinsfile `environment` block.

## Credentials

**Manage Jenkins > Credentials > (folder or system store) > Add Credentials.** Prefer a **folder-scoped** store so only this job can use them.

| ID | Kind | Notes |
|---|---|---|
| `jetbrains-api-token` | Secret text | JetBrains Account API token |
| `jetbrains-customer-code` | Secret text | Customer code |
| `ad-service-account` | Username with password | Read-only AD service account (UPN) |
| `slack-webhook-url` | Secret text | Optional; incoming webhook of a **private** channel |
| `smtp-relay-account` | Username with password | Optional; only if the relay needs auth |

Secrets are bound only inside the stages that need them, passed as environment variables (never as command-line arguments), and used in single-quoted `sh` scripts so Groovy never interpolates them.

Rotation: update the credential in place (same ID), then run a manual dry run. See [jetbrains_setup.md](jetbrains_setup.md#token-rotation) and [active_directory_setup.md](active_directory_setup.md#password-rotation).

## Create the job

1. Put this repository in a **private** Git repository with branch protection on `main` (pull request + review required), because whoever can change `main` controls what runs with the JetBrains and AD credentials.
2. **New Item > Pipeline** (not a Multibranch Pipeline or Organization Folder: those would run the Jenkinsfile of every branch or pull request with the credentials bound), optionally inside a folder, named e.g. `jetbrains-license-cleanup`.
3. **Pipeline > Definition: Pipeline script from SCM**, select the repository and branch `main`, *Script Path* `Jenkinsfile`.
4. Restrict job permissions: only the license administrators group should have *Build*, *Configure* and *Read* (artifacts contain employee emails).
5. Save, then click **Build Now** once. The first build registers the parameters and the cron trigger. It runs in dry-run mode.

## Monthly schedule

The trigger is defined in the Jenkinsfile:

```groovy
@Field def CRON_TZ   = 'Etc/UTC'     // set your zone, e.g. 'Asia/Jerusalem'
@Field def CRON_SPEC = 'H 2 1 * *'   // 02:00-02:59 on the 1st of each month
```

`H` spreads the minute within the 02:xx hour. The `TZ=` line makes the schedule independent of the controller's timezone. Change either value through a reviewed commit.

## How execution mode is decided

| Trigger | `execution.production_enabled` | Other input | Result |
|---|---|---|---|
| Any | `false` | anything | Dry run (a production request fails the build) |
| Scheduled | `true` | `execution.scheduled_mode: dry-run` | Dry run |
| Scheduled | `true` | `execution.scheduled_mode: production` | **Production** (build parameters ignored) |
| Manual | `true` | `DRY_RUN` checked (default) | Dry run |
| Manual | `true` | `DRY_RUN` unchecked | **Production** with the manual parameters |

Scheduled runs are detected with `TimerTrigger` build causes, so a stale parameter value from an earlier manual run can never turn a scheduled run into a production run.

## Stages and build results

1-4 checkout, venv, dependencies (+ `pip-audit`), tests; 5 config and execution-mode validation; 6-7 JetBrains and AD connectivity; 8-12 inventory, AD matching, analysis, plan, safety gate; 13-14 revocation and verification (production only); 15-18 (in `post`) reports, archiving, notification, workspace cleanup. Stages 15-18 run even after failures.

| Build result | Meaning |
|---|---|
| SUCCESS | Everything completed; all revocations verified |
| UNSTABLE | Safety gate blocked revocations, some revocations failed or could not be verified, vulnerable dependencies, or a notification failed |
| FAILURE | Critical problem (config, auth, AD/JetBrains unreachable, incomplete inventory, tests failing). No revocations after the failure point |
| ABORTED | 2-hour timeout or manual abort |

Concurrent builds are prevented (`disableConcurrentBuilds`). Retention: 36 builds / 3 years, artifacts 24 builds / 2 years (adjust `buildDiscarder` to your audit policy).

## Executing a dry run

**Build with Parameters**, leave `DRY_RUN` checked, then open the archived `reports/<execution-id>/license_audit_*.csv`.

## Notifications

Enable Slack and/or email in `config.yaml` (`notifications.slack.enabled`, `notifications.email.*`) and create the matching credentials. Messages contain counts and product breakdowns only, plus links to the build and its artifacts.
