# Expected Response

## System
- Domain: Pharmaceutical / Clinical Trials
- System: TrialVault ClinicalOps API
- Example ID: GQL-0171

## Priority Findings

### Finding 1: Pharma Clinical — Schema Over-Exposure Enables Bulk Cross-Tenant Trial Data Access (Pattern 6.1)
**Severity:** Critical
**Category:** Misconfiguration / Schema/Relationship Over-Exposure

**Summary:**
Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): The GraphQL schema over-exposes clinical trial relationship fields enabling bulk cross-tenant access. An attacker from `tenant-350d` queried `bulkResourceLookup(ids: ["R-2171", "R-1171", "R-3171"])` and received clinical trial data belonging to `tenant-c13c`, including `CONFIDENTIAL-350dc13c`. In Pharmaceutical / Clinical Trials, this exposes trial protocols, patient enrollment data, adverse event reports, and FDA-regulated submissions.

**Evidence from HAR:**
- Request: `POST https://api.trialvault-clinicalo.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-350d`
- Query: `bulkResourceLookup(ids: ["R-2171", "R-1171", "R-3171"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-c13c"`, `ownerId: "other-user-350dc13c"`, `sensitiveField: "CONFIDENTIAL-350dc13c"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-350dc13c`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 6.1 | Schema over-exposure, bulk access |
| HAR request | ids array | R-2171, R-1171, R-3171 (cross-tenant) |
| HAR response | tenantId | tenant-c13c trial data returned |
| HAR response | sensitiveField | CONFIDENTIAL-350dc13c |

## Steps to Reproduce

### Step 1 — Bulk clinical trial lookup (HAR)
```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-350d" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2171\", \"R-1171\", \"R-3171\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-c13c` clinical trial data returned. **Secure:** Only `tenant-350d` data or FORBIDDEN.

## Remediation
1. Restrict schema: remove over-exposed clinical relationship fields.
2. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
3. Disable GraphQL introspection in production.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
