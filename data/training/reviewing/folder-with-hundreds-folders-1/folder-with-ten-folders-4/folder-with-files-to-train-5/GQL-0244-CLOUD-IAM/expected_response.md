# Security Analysis Report
**System:** VaultGuard IAM API (Cloud IAM / Identity Provider)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0244 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.2 | Related/linked resources — cross-tenant IAM identity resource accessed without ownership check |

---

## Finding 1 — BOLA: Cross-Tenant IAM Identity Resource Access via Related Resource (CRITICAL)

### Summary
The `getResource` resolver on VaultGuard IAM API (`api.vaultguard-iam-api.example.com`) fetches resources by `resourceId` only, with no JWT `tenantId` ownership check (§4.0 RISK-GQL-244). Per §5.0 Pattern 1.2, this exploits related/linked resources: IAM identity resources are linked to other objects (roles, policies, credentials) in the graph, and accessing one without ownership verification exposes the entire linked resource tree. An attacker from `tenant-3c33` accesses `R-2244` belonging to `tenant-b5be`, obtaining IAM credentials and identity configurations.

**Pattern:** 1.2 — Related or linked resources (BOLA)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.vaultguard-iam-api.example.com/graphql`

### Evidence from HAR
**Request (attacker `tenant-3c33`):**
```
POST https://api.vaultguard-iam-api.example.com/graphql HTTP/2.0
x-tenant-id: tenant-3c33
{"query": "query VulnerableOp { getResource(id: \"R-2244\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
**Response:** `tenantId: tenant-b5be`, `sensitiveField: CONFIDENTIAL-3c33b5be`, `ownerId: other-user-3c33b5be`
**x-request-id:** `req-3c33b5be`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-244 | No `tenantId` check | Resolver gap | Root cause |
| §5.0 Pattern 1.2 | Related resource BOLA | Classification | IAM linked resources exposed |
| HAR | `id: R-2244` | Victim resource | Cross-tenant IAM credential |
| HAR | `CONFIDENTIAL-3c33b5be` | Sensitive | IAM identity data |
| HAR | `req-3c33b5be` | Correlation ID | Forensics |

### Steps to Reproduce
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "x-tenant-id: tenant-3c33" \
  -d '{"query":"query { getResource(id: \"R-2244\") { resourceId tenantId data { sensitiveField } } }"}'
# VULNERABLE: tenantId=tenant-b5be, sensitiveField=CONFIDENTIAL-3c33b5be
```

### Remediation
1. `if (resource.tenantId !== context.auth.tenantId) throw ForbiddenError()`
2. Apply ownership check to ALL linked/related resource resolvers — child resolvers inherit parent tenancy check.
3. IAM-specific: exposed identity resources can lead to credential theft and privilege escalation across the cloud environment.
4. Fix Redis cache key with `tenantId` (§2.0).
