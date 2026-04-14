# Expected Response

## System
- **Domain:** Education / Assessment Platform
- **System:** LearnPath Assessment Platform
- **Example ID:** GQL-0216

## Priority Findings

### Finding 1: Education Platform — Operational PII Leakage via getResource Exposes Cross-Tenant Student Assessment Data (Pattern 7.1)
**Severity:** High
**Category:** Logging Failures / Operational PII/PHI Leakage

**Summary:**
Per §4.0 (RISK-GQL-216): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): sensitive student assessment data returned in API responses leaks across tenant boundaries through operational data paths without adequate ownership filtering. An attacker from `tenant-7a4a` queried `getResource(id: "R-2216")` and received student assessment records belonging to `tenant-2b89`, including `CONFIDENTIAL-7a4a2b89`. In Education / Assessment Platforms, exposure of student grades, assessment scores, and learning data violates FERPA/COPPA and educational data protection regulations.

**Evidence from HAR:**
- Request: `POST https://api.learnpath-assessment.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-7a4a`
- Query: `getResource(id: "R-2216") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-2b89"`, `ownerId: "other-user-7a4a2b89"`, `sensitiveField: "CONFIDENTIAL-7a4a2b89"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-7a4a2b89`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-216 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 7.1 | Operational PII leakage — student data not tenant-filtered |
| HAR query | id: "R-2216" | Cross-tenant student assessment lookup |
| HAR response | tenantId | tenant-2b89 returned to tenant-7a4a |
| HAR response | sensitiveField | CONFIDENTIAL-7a4a2b89 |
| HAR header | x-request-id | req-7a4a2b89 |

## Steps to Reproduce

### Step 1 — getResource operational PII leakage education (HAR)
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-7a4a" \
  -d '{"query": "query { getResource(id: \"R-2216\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-2b89` student assessment data including `CONFIDENTIAL-7a4a2b89`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Ensure student PII (grades, scores) is never logged in operational logs or returned cross-tenant.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
