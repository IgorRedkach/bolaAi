# Security Analysis Report
**System:** InsightGraph Analytics API (Data Analytics / BI Platform)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0245 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.3 | Bulk/list endpoint — `getResource` without ownership check exposes cross-tenant BI analytics data |

---

## Finding 1 — BOLA: Cross-Tenant Analytics Report Data via Bulk List Access (CRITICAL)

### Summary
The `getResource` resolver on InsightGraph Analytics API (`api.insightgraph-analyti.example.com`) fetches records without JWT `tenantId` ownership enforcement (§4.0 RISK-GQL-245). Per §5.0 Pattern 1.3, this is a bulk/list endpoint BOLA: the resolver serves as a gateway to multiple analytics resources, and without tenancy checks, an attacker can enumerate and access analytics reports, dashboards, and dataset configurations belonging to `tenant-6690`. An attacker from `tenant-a1eb` accesses resource `R-2245`.

**Pattern:** 1.3 — Bulk or list endpoints (BOLA)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.insightgraph-analyti.example.com/graphql`

### Evidence from HAR
**Request (attacker `tenant-a1eb`):**
```
POST https://api.insightgraph-analyti.example.com/graphql HTTP/2.0
x-tenant-id: tenant-a1eb
{"query": "query VulnerableOp { getResource(id: \"R-2245\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
**Response:** `tenantId: tenant-6690`, `sensitiveField: CONFIDENTIAL-a1eb6690`, `ownerId: other-user-a1eb6690`
**x-request-id:** `req-a1eb6690`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-245 | No `tenantId` check | Root cause | Resolver gap |
| §5.0 Pattern 1.3 | Bulk endpoint BOLA | Classification | BI data enumerable |
| HAR | `R-2245` | Victim BI resource | Analytics dataset |
| HAR | `CONFIDENTIAL-a1eb6690` | Sensitive | Analytics report data |
| HAR | `req-a1eb6690` | Correlation ID | Forensics |

### Steps to Reproduce
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "x-tenant-id: tenant-a1eb" \
  -d '{"query":"query { getResource(id: \"R-2245\") { resourceId tenantId data { sensitiveField } } }"}'
# VULNERABLE: tenantId=tenant-6690, sensitiveField=CONFIDENTIAL-a1eb6690
```

### Remediation
1. `if (resource.tenantId !== context.auth.tenantId) throw ForbiddenError()`
2. Apply to all list/bulk endpoints including `listResources` and `bulkResourceLookup`.
3. BI analytics reports may contain trade secrets, business metrics, and financial projections — cross-tenant access is competitive intelligence breach.
4. Fix Redis cache key with `tenantId` (§2.0).
