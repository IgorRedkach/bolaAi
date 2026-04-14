# Security Analysis Report
**System:** WageFlow Payroll API (HR / Payroll Processing)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0246 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.5 | Multi-tenant bulk payroll access — `bulkResourceLookup` returns cross-tenant payroll records |

---

## Finding 1 — Cross-Tenant Bulk Payroll Record Access (CRITICAL)

### Summary
The `bulkResourceLookup` mutation on WageFlow Payroll API (`api.wageflow-payroll-api.example.com`) accepts arbitrary resource IDs without per-ID tenancy ownership validation (§4.0 RISK-GQL-246). Per §5.0 Pattern 1.5, the resolver trusts the client-supplied `tenantId` filter instead of enforcing via JWT. An attacker from `tenant-b3dd` passes payroll resource IDs `["R-2246", "R-1246", "R-3246"]` belonging to `tenant-0e51` and receives employee payroll data, salary records, and PII.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!): [Resource!]`
**Affected endpoint:** `POST https://api.wageflow-payroll-api.example.com/graphql`

### Evidence from HAR
**Request (attacker `tenant-b3dd`):**
```
POST https://api.wageflow-payroll-api.example.com/graphql HTTP/2.0
x-tenant-id: tenant-b3dd
{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2246\", \"R-1246\", \"R-3246\"]) { resourceId tenantId data { sensitiveField } } }"}
```
**Response:** `tenantId: tenant-0e51`, `sensitiveField: CONFIDENTIAL-b3dd0e51`, `ownerId: other-user-b3dd0e51`
**x-request-id:** `req-b3dd0e51`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-246 | No per-ID tenancy check | Root cause | Bulk resolver gap |
| §5.0 Pattern 1.5 | Multi-tenant BOLA | Classification | Payroll data cross-tenant |
| HAR | `["R-2246","R-1246","R-3246"]` | Victim payroll IDs | Bulk access |
| HAR | `CONFIDENTIAL-b3dd0e51` | Sensitive | Employee payroll data |
| HAR | `req-b3dd0e51` | Correlation ID | Forensics |

### Steps to Reproduce
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "x-tenant-id: tenant-b3dd" \
  -d '{"query":"query { bulkResourceLookup(ids: [\"R-2246\",\"R-1246\",\"R-3246\"]) { resourceId tenantId data { sensitiveField } } }"}'
# VULNERABLE: tenant-0e51 payroll records with CONFIDENTIAL-b3dd0e51
```

### Remediation
1. Per-ID filter: `return resources.filter(r => r.tenantId === context.auth.tenantId)`
2. Payroll data is regulated under employment law and GDPR — unauthorized access is a notifiable breach.
3. Non-guessable resource IDs; rate limiting on bulk endpoints.
4. Fix Redis cache key with `tenantId`.
