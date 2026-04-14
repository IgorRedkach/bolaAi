# Expected Response

## System
- **Domain:** Fitness / Health Technology
- **System:** VitalTrack Health API
- **Example ID:** GQL-0181

## Priority Findings

### Finding 1: Fitness Health — BOLA Write Operation Exposes Cross-Tenant Health Data via listResources (Pattern 1.6)
**Severity:** High
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-181): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.6 — write operations without ownership check): the `listResources` endpoint accepts a caller-supplied `tenantId` filter that is not validated against the JWT, allowing cross-tenant data enumeration. An attacker from `tenant-867e` queried `listResources(tenantId: "tenant-b406")` and received health tracking records belonging to `tenant-b406`, including `CONFIDENTIAL-867eb406`. In Fitness / Health Technology, unauthorized access to member health metrics, workout data, and biometric records constitutes a HIPAA/health data privacy violation.

**Evidence from HAR:**
- Request: `POST https://api.vitaltrack-health-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-867e`
- Query: `listResources(tenantId: "tenant-b406") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-b406"`, `ownerId: "other-user-867eb406"`, `sensitiveField: "CONFIDENTIAL-867eb406"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-867eb406`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-181 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.6 | Write/list operation accepts caller-supplied tenantId |
| HAR query | tenantId: "tenant-b406" | Caller-injected cross-tenant filter |
| HAR response | tenantId | tenant-b406 returned to tenant-867e |
| HAR response | sensitiveField | CONFIDENTIAL-867eb406 |
| HAR header | x-request-id | req-867eb406 |

## Steps to Reproduce

### Step 1 — listResources write operation BOLA cross-tenant (HAR)
```bash
curl -s -X POST https://api.vitaltrack-health-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-867e" \
  -d '{"query": "query { listResources(tenantId: \"tenant-b406\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-b406` health records including `CONFIDENTIAL-867eb406`. **Secure:** FORBIDDEN — `tenantId` overridden from JWT; only `tenant-867e` data returned.

## Remediation
1. Ignore caller-supplied `tenantId` argument; always set `tenant_id = $jwt.tenantId` in resolver.
2. Write operations: validate `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
