# Expected Response

## System
- Domain: B2B SaaS / Sales Pipeline
- System: PipelinePro Sales API
- Example ID: GQL-0084

## Priority Findings

### Finding 1: Operational PII Leakage via Logging — Cross-Tenant Sales Pipeline Mutation Logged with Sensitive Data (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures / Operational PII Leakage

**Summary:**
Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): The `updateProject` mutation succeeds cross-tenant and its response (including sensitive sales pipeline data) is captured in application logs. An attacker from `tenant-2b57` mutated project record `P-2084` (belonging to `tenant-b8d4`) with `ownerId: "attacker-2b57b8d4"`. The successful mutation logs the response body including `sensitiveField: "CONFIDENTIAL-2b57b8d4"` with request ID `req-2b57b8d4`, resulting in CRM/sales PII persisting in log aggregation systems beyond the intended security boundary.

**Evidence from HAR:**
- Request: `POST https://api.pipelinepro-sales.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-2b57`
- Mutation: `updateProject(id: "P-2084", input: {status: "approved", ownerId: "attacker-2b57b8d4"}) { projectId status }`
- Response `200 OK`; cross-tenant data: `tenantId: "tenant-b8d4"`, `sensitiveField: "CONFIDENTIAL-2b57b8d4"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-2b57b8d4`
- Note: Domain object is `Project`/`projectId` — resolver is `updateProject`.

## Steps to Reproduce

### Step 1 — Cross-tenant project mutation with logging (HAR)
```bash
curl -s -X POST https://api.pipelinepro-sales.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2b57" \
  -d '{"query": "mutation { updateProject(id: \"P-2084\", input: {status: \"approved\", ownerId: \"attacker-2b57b8d4\"}) { projectId status } }"}'
```
**Vulnerable:** Cross-tenant project mutated; response with `CONFIDENTIAL-2b57b8d4` logged under `req-2b57b8d4`. **Secure:** FORBIDDEN.

### Step 2 — Read cross-tenant project (Pattern 7.1 — response body in logs)
```bash
curl -s -X POST https://api.pipelinepro-sales.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2b57" \
  -d '{"query": "query { getProject(id: \"P-2084\") { projectId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `getProject` also lacks tenantId check; response body logged.

## Remediation
1. Resolver tenant guard on `updateProject` and `getProject`: `WHERE project_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ProjectInput` — never client-writable.
3. Log only `projectId`, `requestId`, and `sub` (not response body or `sensitiveField`).
4. Redis cache key: `project:{tenantId}:{projectId}`.
