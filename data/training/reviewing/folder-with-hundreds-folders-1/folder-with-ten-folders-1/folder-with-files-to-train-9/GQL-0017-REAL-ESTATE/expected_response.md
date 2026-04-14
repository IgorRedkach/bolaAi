## System

- System: EstateFlow Property API v1.0.4
- Domain: REAL ESTATE / PROPTECH
- Example ID: GQL-0017
- Risk ID: RISK-GQL-017

## Findings

### 1. Schema/Relationship Over-Exposure via GraphQL Introspection in Production (Pattern 6.1)

**Primary documented vulnerability**: Section 5.0 explicitly states GraphQL introspection is enabled in production. An attacker can enumerate the complete schema — all types, fields, relationships, and internal field names — without any authorization. This reveals `sensitiveField`, `internalNotes`, `auditLog`, and relationship paths (`items: [Item!]`) that directly enable targeted BOLA exploitation.

**Why this is the primary finding**: without introspection, an attacker must guess field names. With introspection enabled, the attacker can directly discover that `ResourceData` exposes `sensitiveField` (PII-marked), `internalNotes` (internal-only), and `auditLog`, and that `getResourceWithChildren` returns nested `items`. This turns a partial BOLA into a complete data extraction attack.

**Real estate/PropTech impact**: `Resource` objects in a property platform represent listings, deals, or client portfolios. Internal schema exposure reveals field names for confidential deal terms, buyer financial qualifications, and broker notes.

### 2. `listResources` Client-Controlled `tenantId` Override (Pattern 1.5 / HAR Primary)

The HAR shows `listResources(tenantId: "tenant-6cab")` from JWT `tenant-2d4e`. After introspection reveals the full query structure, the attacker uses the discovered schema to craft a targeted `listResources` call with a forged `tenantId`, returning the complete property portfolio of a competing real estate agency.

**HAR evidence**: JWT `x-tenant-id: tenant-2d4e`. Request: `listResources(tenantId: "tenant-6cab")`. Response: HTTP 200 OK with `"tenantId": "tenant-6cab"`, `"sensitiveField": "CONFIDENTIAL-2d4e6cab"`.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-017)

Section 4.0 (RISK-GQL-017): `getResource` fetches by `resourceId` without tenant check.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key.

## Evidence

- **Section 5.0**: Pattern 6.1 — introspection enabled in production, exposes internal field names and relationship paths.
- **HAR**: `listResources(tenantId: "tenant-6cab")` with `tenant-2d4e` JWT → HTTP 200 → `tenantId: tenant-6cab` with `sensitiveField`.
- **Section 4.0 (RISK-GQL-017)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Schema introspection (Pattern 6.1 primary attack):**

```graphql
{ __schema { types { name fields { name description type { name ofType { name } } } } } }
```

Expected secure: Introspection disabled — `"message": "GraphQL introspection is not allowed"`.  
Expected vulnerable: Full schema returned, revealing `sensitiveField`, `internalNotes`, `auditLog`, `items`, and all query/mutation names.

**Step 2 — `listResources` tenant override (HAR primary — enabled by schema discovery):**

```graphql
query { listResources(tenantId: "tenant-6cab") { resourceId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns only records for JWT's `tenantId`.  
Expected vulnerable: HTTP 200 with full property portfolio for `tenant-6cab`.

**Step 3 — Single cross-tenant resource read (RISK-GQL-017):**

```graphql
query { getResource(id: "R-2017") { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { event timestamp } } } }
```

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2017", "R-3017", "R-4017"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Disable GraphQL introspection in production** (Pattern 6.1): `introspection: false` in Apollo Server config.
- **Ignore client-supplied `tenantId` in `listResources`**: source from JWT claims only.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-017).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
