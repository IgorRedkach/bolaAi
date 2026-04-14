# Expected Response

## System
- Domain: Gaming / MMO Backend
- System: RealmForge Game API
- Example ID: GQL-0132

## Priority Findings

### Finding 1: MMO Gaming — Draft Character Data Exposed via Bulk Character Lookup (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §5.0 (Pattern 10.5 — draft/non-published resource access): The `getCharacter` resolver fetches by `characterId` without enforcing ownership, enabling access to draft or unpublished game characters from other tenants. An attacker from `tenant-afcf` queried `bulkCharacterLookup(ids: ["C-2132", "C-1132", "C-3132"])` and received character data belonging to `tenant-4df4`, including `CONFIDENTIAL-afcf4df4`. In MMO Gaming, this exposes unreleased character builds, equipment, stats, and in-game economic data before public release.

**Evidence from HAR:**
- Request: `POST https://api.realmforge-game-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-afcf`
- Query: `bulkCharacterLookup(ids: ["C-2132", "C-1132", "C-3132"]) { characterId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-4df4"`, `ownerId: "other-user-afcf4df4"`, `sensitiveField: "CONFIDENTIAL-afcf4df4"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-afcf4df4`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.5 | Draft character access, no ownership |
| HAR request | ids array | C-2132, C-1132, C-3132 (cross-tenant) |
| HAR response | tenantId | tenant-4df4 returned for tenant-afcf caller |
| HAR response | sensitiveField | CONFIDENTIAL-afcf4df4 |

## Steps to Reproduce

### Step 1 — Bulk character lookup (HAR)
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-afcf" \
  -d '{"query": "query { bulkCharacterLookup(ids: [\"C-2132\", \"C-1132\", \"C-3132\"]) { characterId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-4df4` draft character data returned. **Secure:** Only `tenant-afcf` characters or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE character_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Draft-state gate: characters with `status="draft"` require owner role.
3. Redis cache key: `character:{tenantId}:{characterId}`.
