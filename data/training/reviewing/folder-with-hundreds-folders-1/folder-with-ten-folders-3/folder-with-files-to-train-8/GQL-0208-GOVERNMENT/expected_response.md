# Expected Response

## System
- **Domain:** Government / Emergency Services
- **System:** FirstResponse CAD Integration
- **Example ID:** GQL-0208

## Priority Findings

### Finding 1: Government CAD — BOLA via Mass Assignment in getResource Exposes Cross-Tenant Dispatch Records (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment via Object Fields

**Summary:**
Per §4.0 (RISK-GQL-208): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.12 — mass assignment via object fields): the resolver accepts and returns privileged object fields without tenant scoping, enabling cross-tenant mass assignment and data exposure. An attacker from `tenant-ba72` queried `getResource(id: "R-2208")` and received CAD dispatch records belonging to `tenant-d92d`, including `CONFIDENTIAL-ba72d92d`. In Government / Emergency Services (CAD), unauthorized access to active dispatch records, unit locations, and emergency call data directly endangers first responder safety and public security.

**Evidence from HAR:**
- Request: `POST https://api.firstresponse-cad-in.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-ba72`
- Query: `getResource(id: "R-2208") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-d92d"`, `ownerId: "other-user-ba72d92d"`, `sensitiveField: "CONFIDENTIAL-ba72d92d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ba72d92d`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-208 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.12 | Mass assignment — privileged fields exposed cross-tenant |
| HAR query | id: "R-2208" | Cross-tenant CAD dispatch record lookup |
| HAR response | tenantId | tenant-d92d returned to tenant-ba72 |
| HAR response | sensitiveField | CONFIDENTIAL-ba72d92d |
| HAR header | x-request-id | req-ba72d92d |

## Steps to Reproduce

### Step 1 — getResource mass assignment CAD cross-tenant (HAR)
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ba72" \
  -d '{"query": "query { getResource(id: \"R-2208\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-d92d` CAD dispatch record including `CONFIDENTIAL-ba72d92d`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip all privileged fields (`ownerId`, `tenantId`) from response types for cross-tenant callers.
3. CAD data must be classified and access-logged per CJIS/government compliance standards.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
