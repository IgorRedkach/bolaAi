# Expected Response

## System
- **Domain:** Railway / Critical Rail Infrastructure
- **System:** RailCore Operations API
- **Example ID:** GQL-0188

## Priority Findings

### Finding 1: Railway — Insecure Design via Client-Assumed Authority in getResource Exposes Cross-Tenant Operations Data (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §4.0 (RISK-GQL-188): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 3.1 — client-assumed authority): the resolver trusts the client to supply the correct identity/authority context (e.g., `ownerId`, `tenantId`) rather than deriving it server-side from the JWT. An attacker from `tenant-6ab2` queried `getResource(id: "R-2188")` and received the rail operations record belonging to `tenant-df08`, including `CONFIDENTIAL-6ab2df08`. In Railway / Critical Rail Infrastructure, unauthorized access to signalling, scheduling, and operational data poses a direct public safety risk.

**Evidence from HAR:**
- Request: `POST https://api.railcore-operations-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-6ab2`
- Query: `getResource(id: "R-2188") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-df08"`, `ownerId: "other-user-6ab2df08"`, `sensitiveField: "CONFIDENTIAL-6ab2df08"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-6ab2df08`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-188 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority — resolver trusts client-supplied identity |
| HAR query | id: "R-2188" | Cross-tenant rail operations lookup |
| HAR response | tenantId | tenant-df08 returned to tenant-6ab2 |
| HAR response | sensitiveField | CONFIDENTIAL-6ab2df08 |
| HAR header | x-request-id | req-6ab2df08 |

## Steps to Reproduce

### Step 1 — getResource client-assumed authority insecure design (HAR)
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6ab2" \
  -d '{"query": "query { getResource(id: \"R-2188\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-df08` rail operations record including `CONFIDENTIAL-6ab2df08`. **Secure:** FORBIDDEN — authority derived from JWT only.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Never accept identity/authority context from client request — derive `tenantId` and `userId` exclusively from verified JWT.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
