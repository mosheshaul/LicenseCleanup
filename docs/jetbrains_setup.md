# JetBrains setup

Source: JetBrains Account API documentation (https://www.jetbrains.com/help/organization-guide/jetbrains-account-api.html) and the OpenAPI specification (https://account.jetbrains.com/openapi), checked 25 November 2026.

## How to tell which product you use

| You manage licenses in... | System | Supported here |
|---|---|---|
| JetBrains Console / account.jetbrains.com, licenses assigned to named users by email | **JetBrains Account** | Yes |
| A `*.fls.jetbrains.com` site, or the IDE uses a "License server" URL | **License Vault** (standalone or part of IDE Services) | No, see below |
| An on-premises IDE Services server | **IDE Services** | No, see below |

In JetBrains Account, licenses served to a License Vault or a legacy license server show assignee type `SERVER`; this tool skips them. If most of your seats are floating licenses in License Vault, the relevant usage data is in License Vault's own reports and API (one Bearer token per vault, created under *Settings > License Vault API*). Its endpoint list is only shown inside the vault's admin UI, so it was not implemented here to avoid guessing endpoints. It can be added as a separate client once the specification is exported from your vault.

## 1. Enable the API

Requires the **Manage licensing and billing** permission for the entire organization.

1. Open the JetBrains Console and go to **Organization | Administration**.
2. In the **JetBrains Account API** section click **Enable API**. This applies to the whole organization, including all teams.

## 2. Create the API token

Requires at least the **View licenses** permission to create; revocation needs more (below).

- **Organization token** (recommended): **Organization | Administration > Generate access token**. Covers the entire organization. Only one exists per organization.
- **Team token**: **Licensing | Teams > (team) > Administration > Generate access token**. Covers only that team's licenses. Set `jetbrains.team_ids` in `config.yaml` to the team ID(s).

The token is shown **once**. Copy it straight into Jenkins (next section). JetBrains tokens **do not expire**; they are active until invalidated, and are automatically revoked if the creating user loses the required permission.

## 3. Required permissions

| Operation | Permission of the user who created the token |
|---|---|
| Read licenses (dry run) | View licenses (or Manage purchases) for the organization, or team admin |
| Revoke licenses (production) | **Manage licensing and billing** for the organization, or **team admin** for the team's pool |

Least privilege: create the token from a dedicated, MFA-protected "automation" JetBrains Account that has only the permission you need. For dry runs only, a View-licenses token is enough. Because one organization token exists per organization, consider team tokens if other integrations already use the organization token.

## 4. Customer code

Copy it from the Help menu (*Copy support information*) or from the company name in JetBrains Account. Store it as the `jetbrains-customer-code` Jenkins credential. It is not highly sensitive, but keeping it with the token avoids exposing it in logs.

## 5. Store in Jenkins

| ID | Kind | Value |
|---|---|---|
| `jetbrains-api-token` | Secret text | the token |
| `jetbrains-customer-code` | Secret text | the customer code |

## Token rotation

- Rotate at least yearly, and immediately if exposure is suspected or the creating admin leaves.
- In the console use **Generate new token** (this invalidates the current one immediately), or call `POST /token/rotate` (returns a new token and invalidates the old).
- Update the `jetbrains-api-token` credential in Jenkins straight away, then run the job manually in dry-run mode to confirm.

## API behaviour this tool depends on

- `GET /customer/licenses` `assigned` defaults to `false` (available licenses only), so the tool fetches `assigned=true` and `assigned=false` explicitly.
- `X-Total-Count` must be present; the run aborts otherwise (`jetbrains.require_total_count_header`).
- `POST /customer/licenses/revoke`: when `licenseId` is given, other parameters are ignored. Licenses assigned less than 30 days ago return `400 RECENTLY_ASSIGNED_LICENSE_IS_NOT_AVAILABLE_FOR_REVOKE`. If any of the requested licenses is too new, none are revoked, which is why the tool revokes one license per call.
- Errors use `{"code": "...", "description": "..."}`.
- Rate limits are not documented; HTTP 429 is retried with `Retry-After` and exponential backoff.

## Network

Outbound HTTPS (443/tcp) from the Jenkins agent to `account.jetbrains.com`. If a TLS-inspecting proxy is used, set `HTTPS_PROXY` / `NO_PROXY` in the Jenkinsfile `environment` block and point `jetbrains.ca_bundle` (or `REQUESTS_CA_BUNDLE`) at a PEM file containing your corporate root CA. Certificate verification cannot be turned off.
