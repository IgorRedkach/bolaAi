## System

- System: PatientCore EHR API v2.5.1
- Domain: HEALTHCARE / EHR PLATFORM
- Example ID: GQL-0001
- Risk ID: RISK-GQL-001

## Findings

### 1. BOLA on `getPatient` Query — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-001)

Section 4.0 (RISK-GQL-001): "The `getPatient` resolver fetches by `patientId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." An attacker with `tenant-2922` JWT can substitute any `patientId` value and retrieve PHI records belonging to `tenant-cf40`.

**HAR evidence (note: request/response type mismatch in synthetic artifact)**: the HAR request `postData` shows `updatePatient(id: "P-2001", input: {...})` — a mutation. The response body is structured as `getPatient: {"tenantId": "tenant-cf40", ...}` — a query result. This inconsistency is a synthetic artifact. The critical signal is: a `tenant-2922` JWT received `tenantId: "tenant-cf40"` data including `sensitiveField` and `internalNotes` — cross-tenant PHI access is confirmed regardless of which operation triggered it. JWT `x-tenant-id: tenant-2922` → response `tenantId: tenant-cf40` with `sensitiveField: CONFIDENTIAL-2922cf40` and `internalNotes: Internal data exposed`.

### 2. BOLA on `bulkPatientLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.9, documented)

Section 4.0: "The `bulkPatientLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." This is a confirmed documented vulnerability — not conditional. An attacker can submit multiple cross-tenant `patientId` values in a single bulk request and receive PHI for all matching records.

### 3. Redis Cache Without Tenant Dimension — Cross-Tenant Cache Pollution Risk

Section 2.0: "Redis cache keyed by `patientId` (NOTE: no user dimension in cache key)." A `patientId` cached by one tenant's request can be served to a different tenant's subsequent request for the same ID, bypassing any resolver-level tenant check added later.

## Evidence

- **Section 4.0 (RISK-GQL-001)**: `getPatient` resolver fetches by `patientId` only — explicit documented gap.
- **Section 4.0**: `bulkPatientLookup` lacks per-ID ownership filtering — documented gap.
- **Section 2.0**: Redis cache keyed by `patientId` without user/tenant dimension.
- **HAR trace**: `x-tenant-id: tenant-2922` → response `tenantId: tenant-cf40` with `sensitiveField` and `internalNotes` — cross-tenant PHI access confirmed.

## Reproduction

**Step 1 — Establish attacker baseline:**

```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <TOKEN_TENANT-2922>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getPatient(id: \"P-1001\") { patientId tenantId data { sensitiveField } } }"}'
```

Expected: returns own patient with `tenantId: "tenant-2922"`.

**Step 2 — Cross-tenant `getPatient` (Pattern 1.1):**

```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <TOKEN_TENANT-2922>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getPatient(id: \"P-2001\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getPatient": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-cf40"` and PHI fields.

**Step 3 — Bulk cross-tenant lookup (Pattern 1.9, documented):**

```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer <TOKEN_TENANT-2922>" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { bulkPatientLookup(ids: [\"P-2001\", \"P-3001\", \"P-4001\"]) { patientId tenantId data { sensitiveField } } }"}'
```

Expected secure outcome: only `tenant-2922` patients returned; cross-tenant IDs excluded or errored.  
Expected vulnerable outcome: PHI from `tenant-cf40` and other tenants included in response.

## Remediation

- **Add `tenant_id` WHERE clause to `getPatient` resolver** (RISK-GQL-001): `WHERE patientId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkPatientLookup` results by JWT `tenantId`**: post-fetch filter to exclude any record where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**: change from `patientId` to `patientId:tenantId`.
- **Apply same check to `updatePatient` and `deletePatient`**: write mutations must also verify ownership before executing.
