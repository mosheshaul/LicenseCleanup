# Active Directory setup

## Service account (read-only, least privilege)

1. Create a dedicated user, for example `svc-jb-license-ro`, in a service-accounts OU.
2. **Do not** add it to Domain Admins, Account Operators or any privileged group. Ordinary *Domain Users* membership is enough: authenticated users can read `mail`, `userPrincipalName`, `proxyAddresses`, `sAMAccountName` and `userAccountControl` by default.
   - If your domain has removed default read access (hardened ACLs), delegate **Read** on those five attributes for *User* objects under the base DN only.
3. Set a long random password (25+ characters), "password never expires" only if your policy allows service accounts with managed rotation, and deny interactive logon (`Deny log on locally`, `Deny log on through Remote Desktop Services`).
4. Optionally restrict logon workstations or use an authentication policy silo so it can only authenticate from the Jenkins agent.
5. Store it in Jenkins as **Username with password**, ID `ad-service-account`. Username format: UPN (`svc-jb-license-ro@corp.example.com`).

The client opens the connection with `read_only=True`; it never modifies AD objects.

## LDAPS

- Port **636** (or **3269** for a Global Catalog over TLS if users live in several domains of a forest). Plain LDAP (389) is refused by configuration validation.
- The domain controller certificate must chain to a CA the agent trusts and its name must match `active_directory.server`. Put your enterprise root CA (PEM) on the agent and set `active_directory.ca_certs_file`.
- Test from the agent: `openssl s_client -connect dc01.corp.example.com:636 -CAfile /etc/ssl/certs/corp-root-ca.pem -verify_return_error </dev/null`

## Configuration (`config/config.yaml`)

```yaml
active_directory:
  domain: corp.example.com
  server: dc01.corp.example.com      # a load-balanced name is fine if the certificate covers it
  port: 636
  base_dn: "DC=corp,DC=example,DC=com"
  search_scope: SUBTREE              # SUBTREE | LEVEL | BASE
  connect_timeout_seconds: 10
  search_timeout_seconds: 30
  ca_certs_file: /etc/ssl/certs/corp-root-ca.pem
  allow_samaccountname_fallback: true
  external_domains: [contractor.example.net]
  email_domain_aliases: {old-brand.com: example.com}
```

## Matching logic

For each license email (trimmed, case-insensitive):

1. `mail` = email
2. `userPrincipalName` = email
3. `proxyAddresses` = `smtp:email` (finds aliases and renamed mailboxes; AD compares case-insensitively, so primary `SMTP:` matches too)
4. steps 1-3 again with the domain rewritten via `email_domain_aliases`
5. `sAMAccountName` = local part of the email (only if `allow_samaccountname_fallback`). Always a **weak** match and always sent to manual review, never revoked.

The first step with results wins. Two or more results in that step mean `MULTIPLE_MATCHES` and manual review. All values are escaped (RFC 4515) to prevent LDAP injection. Filters also require `objectCategory=person` and `objectClass=user`.

`ACCOUNTDISABLE` (`0x2`) in `userAccountControl` means disabled.

## Outcomes

| Situation | Status | Effect |
|---|---|---|
| One account, enabled | `ENABLED` | usage rules apply |
| One account, disabled | `DISABLED` | revoke (subject to exclusions, 30-day rule and safety gates) |
| No account | `NOT_FOUND` | manual review, **never** treated as disabled |
| Contractor domain, no account | `EXTERNAL_USER` | manual review |
| Several accounts | `MULTIPLE_MATCHES` | manual review |
| Search error for this user | `LOOKUP_ERROR` | not revoked; counts toward the failure-rate gate |
| DC unreachable or bind fails | stage fails | run aborts, nothing revoked |

## Network

From the Jenkins agent to the domain controllers: **636/tcp** (or 3269/tcp), plus DNS. Nothing else is needed.

## Password rotation

1. Reset the service account password in AD.
2. Immediately update the `ad-service-account` credential in Jenkins.
3. Run the job manually (dry run) to confirm the `Validate Active Directory connectivity` stage passes.
Rotate at least every 90-180 days according to policy, and when anyone with access leaves.
