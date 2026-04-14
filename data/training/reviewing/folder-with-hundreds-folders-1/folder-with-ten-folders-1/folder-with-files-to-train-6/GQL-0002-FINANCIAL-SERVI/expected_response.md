## System

- System: NexaBank Open Finance API v5.8.9
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: GQL-0002
- Risk ID: RISK-GQL-002

## Findings

### 1. BOLA on `bulkAccountLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.9 / 1.2)

The HAR shows the attacker uses `bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"])` with JWT `tenant-4af9`. Section 4.0 documents: "The `bulkAccountLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." The mutation accepts all provided IDs and returns account objects regardless of the `tenantId` of each record. The attacker mixes their own account IDs with foreign ones in the same request.

**HAR evidence**: JWT header `x-tenant-id: tenant-4af9`. Bulk lookup mutation with IDs from multiple tenants. Response: HTTP 200 OK. Response body `"tenantId": "tenant-125d"` — cross-tenant account returned alongside the attacker's own accounts. `"sensitiveField": "CONFIDENTIAL-4af9125d"` and `"internalNotes": "Internal data exposed"` confirm financial PII from `tenant-125d` returned to `tenant-4af9`.

### 2. BOLA on `getAccount` — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-002)

Section 4.0 (RISK-GQL-002) documents: "The `getAccount` resolver fetches by `accountId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." A single account lookup is also vulnerable — any authenticated user can substitute any `accountId` to retrieve cross-tenant account data.

### 3. Redis Cache Without Tenant Dimension — Cached PHI Served Cross-Tenant

Section 2.0 notes: "Redis cache keyed by `accountId` (NOTE: no user dimension in cache key)." An account fetched by `tenant-125d` is cached under `accountId` alone. A subsequent request from `tenant-4af9` for the same `accountId` can receive the cached `tenant-125d` account response without a fresh database query — the tenant check (if later added to the resolver) would be bypassed for cached entries.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-4af9` → `bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"])` → HTTP 200 OK → response `tenantId: tenant-125d` with `sensitiveField` and `internalNotes` for a foreign tenant account.
- **Architecture note** (section 4.0, RISK-GQL-002): `getAccount` resolver fetches by ID only, no `tenantId` check — documented known gap.
- **Bulk lookup** (section 4.0): no per-ID ownership filtering — documented gap.
- **Redis cache** (section 2.0): cache keyed by `accountId` without user/tenant dimension.

## Reproduction

**Step 1 — Attacker baseline:**

```graphql
query { getAccount(id: "A-1002") { accountId tenantId data { sensitiveField } } }
```

Expected: returns `tenantId: "tenant-4af9"` — attacker's own account.

**Step 2 — Single cross-tenant lookup:**

```graphql
query { getAccount(id: "A-2002") { accountId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getAccount": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-125d"` and financial PII.

**Step 3 — Bulk cross-tenant lookup (primary HAR attack):**

```graphql
mutation { bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"]) { accountId tenantId data { sensitiveField } } }
```

Expected secure outcome: only accounts belonging to `tenant-4af9` returned; foreign IDs excluded or returned as errors.  
Expected vulnerable outcome: HTTP 200 with accounts from `tenant-125d` included in the response.

## Remediation

- **Add `tenant_id` WHERE clause to `getAccount` resolver** (RISK-GQL-002): `WHERE accountId = $id AND tenant_id = $jwtTenantId` — return null/forbidden for cross-tenant IDs.
- **Filter `bulkAccountLookup` results by JWT `tenantId`**: after bulk fetch, filter to only include records where `tenant_id = jwtTenantId` — cross-tenant IDs silently excluded.
- **Add `tenantId` to the Redis cache key**: change cache key from `accountId` to `accountId:tenantId` — prevents stale cross-tenant cached responses.
- **Disable GraphQL introspection in production**: prevents schema enumeration of `sensitiveField`, `internalNotes`, and related field names.
