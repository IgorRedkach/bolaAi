# Expected Response

## System
- Domain: Data Analytics / BI Platform
- System: InsightGraph Analytics API
- Example ID: GQL-0145

## Priority Findings

### Finding 1: BI Platform — Semantic Ambiguity in Over-Broad getResource Endpoint Enables Cross-Tenant Data Exfiltration (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity / Over-Broad Endpoints

**Summary:**
Per §5.0 (Pattern 3.3 — semantic ambiguity / over-broad endpoints): The `getResource` endpoint is semantically over-broad, accepting any resource ID across tenant boundaries without endpoint-level scoping. An attacker from `tenant-536b` queried `getResource(id: "R-2145")` and received BI analytics data belonging to `tenant-af2c`, including `CONFIDENTIAL-536baf2c`. In Data Analytics / BI, this exposes sensitive business intelligence reports, customer analytics, and proprietary data models.

**Evidence from HAR:**
- Request: `POST https://api.insightgraph-analyti.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-536b`
- Query: `getResource(id: "R-2145") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-af2c"`, `ownerId: "other-user-536baf2c"`, `sensitiveField: "CONFIDENTIAL-536baf2c"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-536baf2c`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 3.3 | Over-broad getResource endpoint |
| HAR request | x-tenant-id | Attacker tenant-536b |
| HAR response | tenantId | Cross-tenant BI data tenant-af2c |
| HAR response | sensitiveField | CONFIDENTIAL-536baf2c |

## Steps to Reproduce

### Step 1 — getResource via over-broad endpoint (HAR)
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-536b" \
  -d '{"query": "query { getResource(id: \"R-2145\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-af2c` BI data returned. **Secure:** FORBIDDEN.

## Remediation
1. Replace `getResource` with domain-specific resolvers (e.g., `getReport`, `getDashboard`).
2. All resolvers: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Schema design review: narrow endpoints to specific resource types.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
