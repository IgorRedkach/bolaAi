# Expected Response

## System
- Domain: Non-Profit / Grant Management
- System: GrantFlow CRM API
- Example ID: GQL-0127

## Priority Findings

### Finding 1: Grant Management — Schema Over-Exposure Leaks Cross-Tenant Grant Data (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema/Relationship Over-Exposure

**Summary:**
Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): The GraphQL schema exposes relationship fields that allow traversal across tenant boundaries. An attacker from `tenant-4df6` queried `bulkResourceLookup(ids: ["R-2127", "R-1127", "R-3127"])` and received grant management data belonging to `tenant-7b03`, including `CONFIDENTIAL-4df67b03`. In Non-Profit / Grant Management, this exposes confidential grant application details, donor information, and beneficiary records.

**Evidence from HAR:**
- Request: `POST https://api.grantflow-crm-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-4df6`
- Query: `bulkResourceLookup(ids: ["R-2127", "R-1127", "R-3127"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-7b03"`, `ownerId: "other-user-4df67b03"`, `sensitiveField: "CONFIDENTIAL-4df67b03"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4df67b03`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 6.1 | Schema over-exposes relationship fields |
| HAR request | ids array | R-2127, R-1127, R-3127 (cross-tenant) |
| HAR response | tenantId | tenant-7b03 returned for tenant-4df6 caller |
| HAR response | sensitiveField | CONFIDENTIAL-4df67b03 |

## Steps to Reproduce

### Step 1 — Bulk grant lookup exploiting schema over-exposure (HAR)
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4df6" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2127\", \"R-1127\", \"R-3127\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-7b03` grant data returned. **Secure:** Only `tenant-4df6` data or FORBIDDEN.

## Remediation
1. Restrict schema: remove cross-tenant relationship fields; scope all resolvers to `$jwt.tenantId`.
2. Disable GraphQL introspection in production.
3. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
