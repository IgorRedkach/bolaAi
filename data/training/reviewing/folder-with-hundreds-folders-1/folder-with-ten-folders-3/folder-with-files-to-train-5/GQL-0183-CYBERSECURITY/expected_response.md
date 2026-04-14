# Expected Response

## System
- **Domain:** Cybersecurity / Security Operations
- **System:** ThreatLens SOC Platform
- **Example ID:** GQL-0183

## Priority Findings

### Finding 1: SOC Platform — BOLA via Predictable IDs in bulkResourceLookup Exposes Cross-Tenant Threat Intelligence (Pattern 1.8)
**Severity:** High
**Category:** BOLA / Predictable or Sequential IDs

**Summary:**
Per §4.0 (RISK-GQL-183): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.8 — predictable or sequential IDs): resource IDs follow a predictable sequential pattern (`R-2183`, `R-1183`, `R-3183`) that allows an attacker to enumerate cross-tenant threat intelligence records. An attacker from `tenant-fca8` queried `bulkResourceLookup(ids: ["R-2183", "R-1183", "R-3183"])` and received a threat record belonging to `tenant-4c39`, including `CONFIDENTIAL-fca84c39`. In a SOC Platform, exposure of threat indicators, incident data, and detection rules to competing organizations constitutes a critical intelligence breach.

**Evidence from HAR:**
- Request: `POST https://api.threatlens-soc-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-fca8`
- Query: `bulkResourceLookup(ids: ["R-2183", "R-1183", "R-3183"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-4c39"`, `ownerId: "other-user-fca84c39"`, `sensitiveField: "CONFIDENTIAL-fca84c39"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-fca84c39`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-183 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.8 | Predictable/sequential IDs enable enumeration |
| HAR query | ids: sequential R-1183, R-2183, R-3183 | Predictable ID enumeration |
| HAR response | tenantId | tenant-4c39 returned to tenant-fca8 |
| HAR response | sensitiveField | CONFIDENTIAL-fca84c39 |
| HAR header | x-request-id | req-fca84c39 |

## Steps to Reproduce

### Step 1 — bulkResourceLookup predictable ID enumeration (HAR)
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-fca8" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2183\", \"R-1183\", \"R-3183\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-4c39` threat record including `CONFIDENTIAL-fca84c39`. **Secure:** FORBIDDEN — only `tenant-fca8` records returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Use non-predictable UUIDs for resource IDs to prevent enumeration.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
