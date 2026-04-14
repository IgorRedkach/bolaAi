# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: GQL-0167

## Priority Findings

### Finding 1: PropTech — Over-Broad getResource Endpoint Exposes Cross-Tenant Property Records (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity / Over-Broad Endpoints

**Summary:**
Per §5.0 (Pattern 3.3 — semantic ambiguity / over-broad endpoints): The `getResource` endpoint is semantically over-broad, accepting any property record ID without endpoint-level scoping. An attacker from `tenant-c3be` queried `getResource(id: "R-2167")` and received property data belonging to `tenant-f8a4`, including `CONFIDENTIAL-c3bef8a4`. In Real Estate / PropTech, this exposes property valuations, lease agreements, and client financial details.

**Evidence from HAR:**
- Request: `POST https://api.estateflow-property-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c3be`
- Query: `getResource(id: "R-2167") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-f8a4"`, `ownerId: "other-user-c3bef8a4"`, `sensitiveField: "CONFIDENTIAL-c3bef8a4"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c3bef8a4`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 3.3 | Over-broad getResource endpoint |
| HAR request | x-tenant-id | Attacker tenant-c3be |
| HAR response | tenantId | Cross-tenant property data tenant-f8a4 |
| HAR response | sensitiveField | CONFIDENTIAL-c3bef8a4 |

## Steps to Reproduce

### Step 1 — getResource over-broad endpoint (HAR)
```bash
curl -s -X POST https://api.estateflow-property-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c3be" \
  -d '{"query": "query { getResource(id: \"R-2167\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-f8a4` property data returned. **Secure:** FORBIDDEN.

## Remediation
1. Replace `getResource` with `getProperty`/`getListing`; scope each resolver.
2. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
