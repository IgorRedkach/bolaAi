## System

- System: PayBridge Transaction API v5.1.5
- Domain: FINTECH / PAYMENTS GATEWAY
- Example ID: GQL-0020
- Risk ID: RISK-GQL-020

## Findings

### 1. `listResources` Client-Controlled `tenantId` — Single Token Accesses Full Payment Tenant (Pattern 10.1 / HAR Primary)

**Primary HAR attack**: The HAR shows `listResources(tenantId: "tenant-151b")` from JWT `tenant-2fef`. Pattern 10.1 (Single-User ID Swap): a single authenticated user with one valid token substitutes the target `tenantId` directly in the query argument — no credential theft, no privilege escalation, just one ID change.

**HAR evidence**: JWT `x-tenant-id: tenant-2fef`. Request: `listResources(tenantId: "tenant-151b")`. Response: HTTP 200 OK with `"tenantId": "tenant-151b"`, `"sensitiveField": "CONFIDENTIAL-2fef151b"` — an entire payment merchant's transaction list returned with a single query argument change.

**Fintech/PCI DSS impact**: `Resource` objects in a payments gateway represent transactions, payment method tokens, or merchant settlement records. The `sensitiveField` in this context likely contains cardholder data or financial account identifiers. Single-token cross-tenant access to transaction records constitutes a PCI DSS breach and may expose payment credentials of another merchant's customers.

### 2. BOLA on `getResource` — Single-ID Swap (RISK-GQL-020 / Pattern 10.1 Canonical)

Section 4.0 (RISK-GQL-020): `getResource` fetches by `resourceId` without tenant check. Section 5.0 describes Pattern 10.1 as a user substituting their valid `resourceId` with a victim's — the simplest possible BOLA with no special tools required.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key. Payment records cached without tenant dimension could serve cross-merchant transaction data.

## Evidence

- **HAR**: `listResources(tenantId: "tenant-151b")` with `tenant-2fef` JWT → HTTP 200 → `tenantId: tenant-151b` with `sensitiveField`.
- **Section 5.0**: Pattern 10.1 — single user swaps `resourceId` (or `tenantId`) with victim's to access their data.
- **Section 4.0 (RISK-GQL-020)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { listResources(tenantId: "tenant-2fef") { resourceId tenantId data { sensitiveField } } }
```

Expected: All records belong to `tenant-2fef`.

**Step 2 — Single-token tenant override (Pattern 10.1 / primary HAR attack):**

```graphql
query { listResources(tenantId: "tenant-151b") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns only records for JWT's `tenantId`.  
Expected vulnerable: HTTP 200 with all payment transaction records for `tenant-151b`.

**Step 3 — Single-ID swap (Pattern 10.1 canonical / RISK-GQL-020):**

```graphql
query { getResource(id: "R-2020") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Replace `R-1020` (own record) with `R-2020` (victim record) — no other change required.  
Expected secure: HTTP 403/404.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-151b"` and payment record data.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2020", "R-3020", "R-4020"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Ignore client-supplied `tenantId` in `listResources`**: source exclusively from JWT `tenantId`.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-020).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
- **PCI DSS scope**: any cross-tenant access to cardholder data is a reportable incident — add real-time alerting on `tenantId` mismatch in response.
