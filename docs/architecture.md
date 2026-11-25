# Architecture

## Integration choice

Organizations buy and assign JetBrains licenses in **JetBrains Account** (managed through the JetBrains Console). This is the system of record for named-user licenses, and it has an official REST API:

| Need | Official API support (JetBrains Account API, `https://account.jetbrains.com/api/v1`) |
|---|---|
| Products | `GET /products` (dictionary) plus product info on every license |
| Licenses, users, emails, license IDs | `GET /customer/licenses` / `GET /customer/teams/{teamId}/licenses` (`licenseId`, `product`, `team`, `assignee.email`, `assignee.name`) |
| Assignment date | `lastSeen.lastAssignmentDate` |
| Last usage | `lastSeen.lastSeenDate` (per license), `lastSeen.isOfflineCodeGenerated` |
| Revoke one license | `POST /customer/licenses/revoke?licenseId=...` (only if assigned for at least 30 days) |
| Verify | `GET /customer/licenses/{licenseId}` |
| Pagination | `page`, `perPage` query parameters; `Link`, `X-Total-Count` headers |
| Auth | `X-Api-Key` (token) and `X-Customer-Code` headers |

**License Vault** (floating licenses, `https://<company>.fls.jetbrains.com`, Bearer token) and **IDE Services** have their own API. Its endpoint specification is only available inside the License Vault admin UI and could not be verified, so it is not implemented. If your organization uses License Vault, those licenses show up in the Account API with assignee type `SERVER` and are skipped. See [jetbrains_setup.md](jetbrains_setup.md#how-to-tell-which-product-you-use).

No browser automation is used.

## Component diagram

```mermaid
flowchart LR
    subgraph Jenkins["Jenkins controller / agent"]
        JF[Jenkinsfile<br/>monthly cron + manual]
        CM[(Credentials Manager)]
        subgraph PY["license_cleanup (Python)"]
            MAIN[main.py<br/>stage CLI]
            CFG[config_manager]
            JBC[jetbrains_client]
            ADC[ad_client]
            LM[license_manager<br/>rules + revocation]
            SC[safety_checks]
            RG[report_generator]
            NM[notification_manager]
            LOG[logger<br/>secret redaction]
        end
        ART[(Archived reports<br/>CSV + JSON)]
    end
    GIT[(Git repo<br/>config.yaml, exclusions.yaml)]
    JBA[JetBrains Account API<br/>account.jetbrains.com:443]
    AD[Active Directory<br/>LDAPS :636]
    SL[Slack webhook / SMTP relay]

    GIT --> JF
    CM -- per-stage env vars --> MAIN
    JF --> MAIN
    MAIN --> CFG
    MAIN --> JBC --> JBA
    MAIN --> ADC --> AD
    MAIN --> LM
    LM --> SC
    MAIN --> RG --> ART
    MAIN --> NM --> SL
```

## Pipeline data flow

Each Jenkins stage calls one CLI sub-command. State passes between stages as JSON files in `$WORKSPACE/.state` (mode 700/600, deleted by `cleanWs`).

```mermaid
sequenceDiagram
    participant J as Jenkins
    participant P as license_cleanup
    participant JB as JetBrains API
    participant AD as Active Directory
    J->>P: init (resolve dry-run vs production)
    J->>P: check-jetbrains
    P->>JB: GET /token
    J->>P: check-ad
    P->>AD: LDAPS bind + base search
    J->>P: inventory
    P->>JB: GET /products, GET /customer/licenses?assigned=true|false&page=N
    J->>P: match-ad
    P->>AD: search mail / UPN / proxyAddresses / sAMAccountName
    J->>P: analyze, plan, safety-check
    alt production and safety gate passed
        J->>P: revoke
        loop each candidate
            P->>JB: GET /customer/licenses/{id} (revalidate)
            P->>AD: re-query (disabled users)
            P->>JB: POST /customer/licenses/revoke?licenseId={id}
            P->>JB: GET /customer/licenses/{id} (verify)
        end
        J->>P: verify
    end
    J->>P: report, notify
```

## Business logic flowchart

```mermaid
flowchart TD
    A[License from inventory] --> B{Assigned?}
    B -- no --> SKIP[SKIP]
    B -- yes --> C{Assignee type USER?}
    C -- no: server or key --> SKIP
    C -- yes --> D{Excluded?}
    D -- yes --> KEEP[KEEP]
    D -- no --> E{AD lookup}
    E -- error --> DNR[DO NOT REVOKE]
    E -- not found / multiple / external / weak match --> MR[MANUAL REVIEW]
    E -- disabled --> F{Revoke disabled users on?}
    F -- no --> KEEP
    F -- yes --> AGE{Assigned >= 30 days?}
    E -- enabled --> G{Offline code generated?}
    G -- yes --> MR
    G -- no --> H{lastSeenDate present?}
    H -- no --> MR
    H -- yes --> I{lastSeenDate before assignment?}
    I -- yes --> MR
    I -- no --> J{lastSeenDate < now - N calendar months?}
    J -- no --> KEEP
    J -- yes --> K{Revoke inactive users on?}
    K -- no --> KEEP
    K -- yes --> AGE
    AGE -- no --> MR
    AGE -- yes --> REV[REVOKE candidate]
    REV --> S{Safety gates pass?<br/>inventory complete, AD failures, count, %}
    S -- no --> BLOCK[Blocked: nothing revoked, alert]
    S -- yes --> DR{Dry run?}
    DR -- yes --> REP[Report only]
    DR -- no --> RV{Revalidate: same assignee,<br/>still eligible?}
    RV -- no --> SKIPR[Skipped after revalidation]
    RV -- yes --> POST[Revoke by licenseId]
    POST --> VER{Verified by re-read?}
    VER -- yes --> DONE[REVOKED + VERIFIED]
    VER -- no --> FAIL[FAILED / UNCERTAIN, no blind retry]
```

## Key design decisions

- **Per-license evaluation.** Usage is recorded per license, so each product assignment is judged independently. A disabled user loses every eligible license; an enabled user loses only the stale ones.
- **Safe defaults.** Dry run unless the reviewed config sets `production_enabled: true`; scheduled runs read only `scheduled_mode` from the config and ignore build parameters.
- **Fail closed.** Incomplete pagination, schema surprises, AD connection/auth failures, excessive lookup failures or too many candidates stop all revocations. Missing data never becomes a revocation.
- **Single-license writes.** Revocation always passes `licenseId` and never `email` (which would revoke all of a user's licenses).
- **No blind retries on writes.** Timeouts and 5xx on revoke are treated as *uncertain*, and the license is re-read to learn the actual state.
- **Idempotent.** Re-running revalidates against live data: already-revoked licenses are skipped, reassigned licenses are left alone, and a license ID is attempted at most once per run.
- **Read-only AD.** The AD client only binds and searches (`read_only=True`), escapes all filter values and requires certificate validation.
