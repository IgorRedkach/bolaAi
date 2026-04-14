# Expected Response

## System
- **Domain:** Gaming / Online Multiplayer
- **System:** RealmForge Game API
- **Example ID:** GQL-0182

## Priority Findings

### Finding 1: Gaming — BOLA via getCharacter Nested Resource Exposes Cross-Tenant Game Account Data (Pattern 1.7)
**Severity:** High
**Category:** BOLA / Nested Resources Without Parent Authorization

**Summary:**
Per §4.0 (RISK-GQL-182): The `getCharacter` resolver fetches by `characterId` only, without verifying `tenantId` ownership of the parent game account. Per §5.0 (Pattern 1.7 — nested resources without parent authorization): a nested resource (character) is accessible without verifying that the parent account belongs to the requesting tenant. An attacker from `tenant-228c` queried `getCharacter(id: "C-2182")` and received the character record belonging to `tenant-7c62`, including `CONFIDENTIAL-228c7c62`. In Gaming / Online Multiplayer, unauthorized access to character inventories, progression data, and in-game economy assets enables cheating, item theft, and competitive exploitation.

**Evidence from HAR:**
- Request: `POST https://api.realmforge-game-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-228c`
- Query: `getCharacter(id: "C-2182") { characterId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-7c62"`, `ownerId: "other-user-228c7c62"`, `sensitiveField: "CONFIDENTIAL-228c7c62"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-228c7c62`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-182 | getCharacter resolver lacks tenantId parent ownership check |
| context.txt §5.0 | Pattern 1.7 | Nested resource (character) without parent auth |
| HAR query | id: "C-2182" | Cross-tenant character lookup |
| HAR response | tenantId | tenant-7c62 returned to tenant-228c |
| HAR response | sensitiveField | CONFIDENTIAL-228c7c62 |
| HAR header | x-request-id | req-228c7c62 |

## Steps to Reproduce

### Step 1 — getCharacter nested resource BOLA (HAR)
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-228c" \
  -d '{"query": "query { getCharacter(id: \"C-2182\") { characterId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-7c62` character record including `CONFIDENTIAL-228c7c62`. **Secure:** FORBIDDEN — character's parent account must belong to `tenant-228c`.

## Remediation
1. Resolver: `WHERE character_id = $id AND tenant_id = $jwt.tenantId` (join through parent account).
2. Enforce parent resource ownership check before resolving nested character fields.
3. Redis cache key: `character:{tenantId}:{characterId}`.
