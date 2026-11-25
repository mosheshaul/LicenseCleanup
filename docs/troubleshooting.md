# Troubleshooting

Start with the console log (timestamped) and `reports/<execution-id>/execution_summary_*.json` (`overall_status`, `errors`, `safety.violations`).

| Symptom | Likely cause | Fix |
|---|---|---|
| `Missing required secret environment variable(s): ...` | Credential ID missing or wrong in Jenkins | Create the credential with the exact ID from [jenkins_setup.md](jenkins_setup.md#credentials) |
| `Configuration key '...' looks like a secret` | A token or password was put in YAML | Remove it from YAML (and from Git history), store it in Jenkins, rotate it |
| `Production mode requested but execution.production_enabled is false` | `DRY_RUN` unchecked without approval in config | Expected. Follow [Enabling production mode](../README.md#enabling-production-mode-safely) |
| `JetBrains API rejected the credentials ... HTTP 401` | Token invalid, rotated, revoked, or API disabled | Generate a new token, update `jetbrains-api-token`; check that the API is enabled |
| `... HTTP 403` | Wrong customer code, or the token owner lacks permission (e.g. View-only token in production; team token used on the organization endpoint) | Check `jetbrains-customer-code`; use a Manage licensing token; set `jetbrains.team_ids` for team tokens |
| `GET ... returned HTTP 429` repeatedly | Rate limited | The client backs off automatically; raise `jetbrains.max_retries`/`backoff_max_seconds` or run at a quieter time |
| `HTTP 5xx` / network errors after retries | JetBrains outage, proxy, firewall | Check `HTTPS_PROXY`, firewall to `account.jetbrains.com:443`, JetBrains status |
| `SSLError` / certificate verify failed | TLS-inspecting proxy with corporate CA | Set `jetbrains.ca_bundle` (or `REQUESTS_CA_BUNDLE`) to your CA bundle. Never disable verification |
| `X-Total-Count header missing` / `collected N but API reported M` | Inventory incomplete or changed during paging | Re-run. If persistent, open a JetBrains support case. The run aborts before any revocation |
| `Duplicate license id ... in inventory` | Inconsistent API pages | Re-run; licenses changed during the run |
| `Cannot connect to ... over LDAPS` | Firewall, DNS, wrong port, DC down | Test `openssl s_client -connect <dc>:636` from the agent |
| LDAPS certificate errors | DC cert not trusted, or hostname mismatch | Set `active_directory.ca_certs_file`; use the hostname in the certificate |
| `Active Directory bind failed` | Wrong password, account locked/expired | Reset and update `ad-service-account` |
| `userAccountControl missing or unreadable` | Hardened ACLs | Delegate Read on `userAccountControl` to the service account |
| `SAFETY GATE: ... exceed MAX_REVOCATIONS` | More candidates than allowed | Review the plan CSV; if correct, run manually with a higher `MAX_REVOCATIONS` (<= `hard_max_revocations`) or raise limits in config through review |
| `SAFETY GATE: AD lookup failure rate ...` | Many per-user search errors | Fix AD connectivity/permissions and re-run |
| Many `MANUAL_REVIEW` with "usage date unavailable" | Licenses never used since assignment, or offline activation | Review manually; contact users |
| `JetBrains refused: license assigned less than 30 days ago` | JetBrains 30-day rule | It will be eligible next month |
| `Result=UNCERTAIN` | Revoke call timed out or got 5xx and the re-read still showed the license assigned | Check the license in the JetBrains console. The next run revalidates and retries only if still eligible |
| `SKIPPED_AFTER_REVALIDATION` | License changed between inventory and revocation (reassigned, already revoked, user re-enabled, recent usage) | Expected safety behaviour |
| `pip-audit` makes the build UNSTABLE | Vulnerable pinned dependency, or no access to the vulnerability DB | Bump the pin in `requirements.txt` via PR and re-run tests |
| Notification not received | Channel not enabled, credential missing, webhook revoked | Check `notifications.*` and the optional credentials |

## Debugging locally

```bash
. .venv/bin/activate
python -m license_cleanup run --config config/config.yaml --log-level DEBUG
ls .state/          # intermediate JSON per stage (contains personal data: delete afterwards)
```

Even at DEBUG, secrets are redacted by the logging filter, and HTTP headers are never logged.
