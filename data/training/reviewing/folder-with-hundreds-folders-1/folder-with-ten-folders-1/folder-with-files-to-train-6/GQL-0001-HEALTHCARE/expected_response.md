## System

- System: PatientCore EHR API v2.5.1
- Domain: HEALTHCARE / EHR PLATFORM (HIPAA)
- Example ID: GQL-0001
- Risk ID: RISK-GQL-001

## Findings

### 1. BOLA on `getPatient` — Missing `tenant_id` Filter in Resolver (Pattern 1.1)

The `getPatient` resolver (section 4.0, RISK-GQL-001) fetches by `patientId` only without cross-checking the JWT's `tenantId`:

> "The `getPatient` resolver fetches by `patientId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

A user with a valid `tenant-2922` JWT can query `getPatient(id: "P-2001")` where `P-2001` belongs to `tenant-cf40`. The response returns the full patient object including `sensitiveField` and `internalNotes` — cross-tenant PHI exposure.

**HAR evidence**: JWT header `x-tenant-id: tenant-2922`. Response body: `"tenantId": "tenant-cf40"` — mismatch confirms cross-tenant access. Response: HTTP 200 OK with `"sensitiveField": "CONFIDENTIAL-2922cf40"` and `"internalNotes": "Internal data exposed"`.

### 2. BOLA on `updatePatient` Mutation — Same Missing Tenant Check (Pattern 1.1 write variant)

The HAR shows the attacker uses an `updatePatient(id: "P-2001", input: {status: "approved", ownerId: "attacker-2922cf40"})` mutation — not a read query — against patient `P-2001` belonging to `tenant-cf40`. The mutation succeeds with HTTP 200 OK, returning the updated cross-tenant object. This means write-path BOLA is also present — an attacker from `tenant-2922` can both read AND modify patient records belonging to `tenant-cf40`.

### 3. `bulkPatientLookup` Mutation — No Per-ID Ownership Filtering (Pattern 1.9)

Section 4.0 documents: "The `bulkPatientLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." Any authenticated user can submit an array of patient IDs from multiple tenants and receive all matching objects — bypassing tenant isolation in bulk.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-2922`; mutation updates `P-2001`; response `tenantId: tenant-cf40`; HTTP 200 OK with cross-tenant PHI (`sensitiveField`, `internalNotes`).
- **Architecture note** (section 4.0, RISK-GQL-001): `getPatient` resolver fetches by `patientId` only, no `tenantId` WHERE clause — documented known gap.
- **Bulk lookup** (section 4.0): `bulkPatientLookup` accepts arbitrary IDs without per-ID ownership filter.
- **Redis cache** (section 2.0): cache keyed by `patientId` only (no user dimension) — cached cross-tenant responses could be served to subsequent callers.

## Reproduction

**Step 1 — Attacker baseline (own tenant):**

```graphql
query { getPatient(id: "P-1001") { patientId tenantId data { sensitiveField } } }
```

Expected: returns `tenantId: "tenant-2922"`.

**Step 2 — Cross-tenant ID substitution:**

```graphql
query { getPatient(id: "P-2001") { patientId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: HTTP 200 with `{"errors": [{"message": "Forbidden"}], "data": {"getPatient": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-cf40"` and full PHI returned.

**Step 3 — Cross-tenant mutation (write BOLA):**

```graphql
mutation { updatePatient(id: "P-2001", input: {status: "approved"}) { patientId tenantId status } }
```

Expected secure outcome: HTTP 200 with `{"errors": [{"message": "Forbidden"}]}`.  
Expected vulnerable outcome: HTTP 200 with updated cross-tenant patient record returned.

**Step 4 — Bulk enumeration:**

```graphql
mutation { bulkPatientLookup(ids: ["P-2001", "P-3001", "P-4001"]) { patientId tenantId data { sensitiveField } } }
```

Expected vulnerable outcome: patients from multiple tenants returned in a single response.

## Remediation

- **Add `tenant_id` to every resolver WHERE clause** (RISK-GQL-001): `WHERE patientId = $id AND tenant_id = $jwtTenantId` for `getPatient`, `updatePatient`, and `deletePatient` — a fetched object with a different `tenantId` must be treated as not found.
- **Filter `bulkPatientLookup` results by JWT `tenantId`**: after fetching by IDs, filter the result set to only include records where `tenant_id = jwtTenantId` — cross-tenant IDs silently excluded or returned as errors.
- **Add `tenantId` to the Redis cache key**: change cache key from `patientId` to `patientId:tenantId` — prevents cached cross-tenant responses from being served to different tenant callers.
- **Disable GraphQL introspection in production** to prevent schema enumeration of field names (`internalNotes`, `sensitiveField`).
