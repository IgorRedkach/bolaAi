# Security Analysis Report
**System:** TaxGrid Compliance API (Tax Compliance / RegTech)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0248 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.7 | Nested resource write without parent authorization — cross-tenant tax compliance record mutated |

---

## Finding 1 — Nested Resource Write: Cross-Tenant Tax Compliance Record Mutation (CRITICAL)

### Summary
The `updateResource` resolver on TaxGrid Compliance API (`api.taxgrid-compliance-a.example.com`) applies mutations to nested compliance resources without verifying the authenticated tenant owns the parent object (§4.0 RISK-GQL-248). Per §5.0 Pattern 1.7, nested resources inherit their parent's ownership — but the resolver does not check this chain. An attacker from `tenant-153d` mutates tax compliance resource `R-2248` belonging to `tenant-e554`, injecting `status: "approved"` — which in a compliance context could falsely mark a tax filing as complete.

**Pattern:** 1.7 — Nested resources without parent authorization (BOLA)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.taxgrid-compliance-a.example.com/graphql`

### Evidence from HAR
**Request (attacker `tenant-153d`):**
```
POST https://api.taxgrid-compliance-a.example.com/graphql HTTP/2.0
x-tenant-id: tenant-153d
{"query": "query VulnerableOp { updateResource(id: \"R-2248\", input: {status: \"approved\", ownerId: \"attacker-153de554\"}) { resourceId status } }"}
```
**Response:** `tenantId: tenant-e554`, `sensitiveField: CONFIDENTIAL-153de554`, `ownerId: other-user-153de554`
**x-request-id:** `req-153de554`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-248 | No `tenantId` check | Root cause | Nested write gap |
| §5.0 Pattern 1.7 | Nested resource BOLA | Classification | Parent auth not checked |
| HAR | `R-2248` | Victim compliance resource | |
| HAR | `status: approved` | Forged compliance status | Tax fraud risk |
| HAR | `CONFIDENTIAL-153de554` | Tax filing data | |
| HAR | `req-153de554` | Correlation ID | |

### Steps to Reproduce
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "x-tenant-id: tenant-153d" \
  -d '{"query":"mutation { updateResource(id: \"R-2248\", input: {status: \"approved\", ownerId: \"attacker-153de554\"}) { resourceId tenantId data { sensitiveField } } }"}'
# VULNERABLE: approves tenant-e554 tax record, sensitiveField=CONFIDENTIAL-153de554
```

### Remediation
1. Pre-mutation tenancy check for both parent and nested resources.
2. Strip client-supplied `ownerId` — server sets from JWT.
3. Tax compliance: falsely approving a tax filing constitutes tax fraud; compliance status changes must be immutable audit log entries.
4. Fix Redis cache key with `tenantId`.
