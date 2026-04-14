## System

- System: NexaBank Open Finance API v5.8.9
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: GQL-0002
- Risk ID: RISK-GQL-002

## Findings

### 1. BOLA on `bulkAccountLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.2 / 1.9)

The HAR shows the attacker sends `bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"])` with JWT `tenant-4af9`. Section 4.0 documents: "The `bulkAccountLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." The attacker mixes their own account IDs with cross-tenant IDs in a single bulk request. HTTP 200 OK is returned with account records from `tenant-125d`.

**HAR evidence**: JWT `x-tenant-id: tenant-4af9`. Bulk lookup mutation with mixed-tenant IDs. Response: HTTP 200 OK. Response body `"tenantId": "tenant-125d"` with `"sensitiveField": "CONFIDENTIAL-4af9125d"` and `"internalNotes": "Internal data exposed"` — financial account data from `tenant-125d` returned to `tenant-4af9`.

### 2. BOLA on `getAccount` — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-002)

Section 4.0 (RISK-GQL-002): "The `getAccount` resolver fetches by `accountId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Direct single-account lookup is also vulnerable.

### 3. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `accountId` (NOTE: no user dimension in cache key)." Cross-tenant account data cached without a tenant dimension can be served to subsequent callers from any tenant.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-4af9` → `bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"])` → HTTP 200 → `tenantId: tenant-125d` with `sensitiveField` and `internalNotes`.
- **Section 4.0 (RISK-GQL-002)**: `getAccount` resolver lacks tenant check — documented.
- **Section 4.0**: `bulkAccountLookup` lacks per-ID filter — documented.
- **Section 2.0**: Redis cache keyed by `accountId` only.

## Reproduction

**Step 1 — Establish attacker baseline:**

```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer <TOKEN_TENANT-4AF9>" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { getAccount(id: \"A-1002\") { accountId tenantId data { sensitiveField } } }"}'
```

Expected: returns `tenantId: "tenant-4af9"` — attacker's own account.

**Step 2 — Bulk cross-tenant lookup (primary HAR attack):**

```graphql
mutation { bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"]) { accountId tenantId data { sensitiveField } } }
```

Expected secure outcome: only `tenant-4af9` accounts returned; foreign IDs excluded or errored.  
Expected vulnerable outcome: HTTP 200 with `tenant-125d` account data.

**Step 3 — Single cross-tenant account lookup:**

```graphql
query { getAccount(id: "A-2002") { accountId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getAccount": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-125d"` and financial PII.

## Remediation

- **Add `tenant_id` WHERE clause to `getAccount` resolver** (RISK-GQL-002): `WHERE accountId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkAccountLookup` results post-fetch**: exclude records where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**: change from `accountId` to `accountId:tenantId`.
- **Scope `updateAccount` and `deleteAccount` mutations**: write operations must also check tenant ownership.
