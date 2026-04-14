# Expected Response

## System
- Domain: Automotive / Connected Car
- System: AetherDrive V2X Telematics
- Example ID: GQL-0155

## Priority Findings

### Finding 1: V2X Telematics — BOLA ID in Path Enables Cross-Tenant Vehicle Data Access (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §5.0 (Pattern 1.1 — ID in path without ownership check): The `bulkResourceLookup` resolver accepts arbitrary resource IDs without verifying tenancy. An attacker from `tenant-ffbf` queried `bulkResourceLookup(ids: ["R-2155", "R-1155", "R-3155"])` and received V2X telematics data belonging to `tenant-fe0f`, including `CONFIDENTIAL-ffbffe0f`. In Automotive / Connected Car, this exposes vehicle telematics (GPS, speed, diagnostics), OTA update configurations, and V2X communication data — enabling vehicle tracking and potentially unsafe remote access.

**Evidence from HAR:**
- Request: `POST https://api.aetherdrive-v2x-tele.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-ffbf`
- Query: `bulkResourceLookup(ids: ["R-2155", "R-1155", "R-3155"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-fe0f"`, `ownerId: "other-user-ffbffe0f"`, `sensitiveField: "CONFIDENTIAL-ffbffe0f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ffbffe0f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.1 | BOLA ID in path, no ownership check |
| HAR request | ids array | R-2155, R-1155, R-3155 (cross-tenant) |
| HAR response | tenantId | Cross-tenant V2X data tenant-fe0f |
| HAR response | sensitiveField | CONFIDENTIAL-ffbffe0f |

## Steps to Reproduce

### Step 1 — Bulk V2X resource lookup (HAR)
```bash
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ffbf" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2155\", \"R-1155\", \"R-3155\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-fe0f` V2X telematics data returned. **Secure:** Only `tenant-ffbf` data or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk array size; rate-limit telematics bulk queries.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
4. V2X data: apply additional encryption for GPS/location fields.
