# Expected Response

## System
- **Domain:** Non-Profit / Grant Management
- **System:** GrantFlow CRM API
- **Example ID:** GQL-0177

## Priority Findings

### Finding 1: Non-Profit CRM — BOLA via getResource ID in Path Exposes Cross-Tenant Grant Records (Pattern 1.1)
**Severity:** High
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-177): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.1 — ID in path without ownership check): any authenticated user can retrieve any grant record by supplying a known `resourceId`. An attacker from `tenant-e221` queried `getResource(id: "R-2177")` and received the record belonging to `tenant-5ba7`, including `CONFIDENTIAL-e2215ba7`. In Non-Profit / Grant Management, unauthorized access to grant applications, donor data, and beneficiary records constitutes a serious privacy violation and may breach grant compliance requirements.

**Evidence from HAR:**
- Request: `POST https://api.grantflow-crm-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e221`
- Query: `getResource(id: "R-2177") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-5ba7"`, `ownerId: "other-user-e2215ba7"`, `sensitiveField: "CONFIDENTIAL-e2215ba7"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e2215ba7`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-177 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.1 | ID in path without ownership check |
| HAR query | id: "R-2177" | Cross-tenant grant record lookup |
| HAR response | tenantId | tenant-5ba7 returned to tenant-e221 |
| HAR response | sensitiveField | CONFIDENTIAL-e2215ba7 |
| HAR header | x-request-id | req-e2215ba7 |

## Steps to Reproduce

### Step 1 — getResource BOLA cross-tenant access (HAR)
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e221" \
  -d '{"query": "query { getResource(id: \"R-2177\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-5ba7` grant record including `CONFIDENTIAL-e2215ba7`. **Secure:** FORBIDDEN — only records owned by `tenant-e221` accessible.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Apply PostgreSQL row-level security policy: `USING (tenant_id = current_setting('app.tenant_id'))`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
