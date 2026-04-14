# Expected Response

## System
- **Domain:** Telemedicine / Remote Healthcare
- **System:** TeleCare Consultation API
- **Example ID:** GQL-0186

## Priority Findings

### Finding 1: Telemedicine — BOLA via Mass Assignment in getResource Exposes Cross-Tenant Patient Consultation Data (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment via Object Fields

**Summary:**
Per §4.0 (RISK-GQL-186): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.12 — mass assignment via object fields): the resolver accepts and processes object-level fields from client input without stripping privileged fields, allowing cross-tenant mass assignment. An attacker from `tenant-8f65` queried `getResource(id: "R-2186")` and received the consultation record belonging to `tenant-0a51`, including `CONFIDENTIAL-8f650a51`. In Telemedicine / Remote Healthcare, unauthorized access to patient consultation records, diagnoses, and prescriptions constitutes a HIPAA violation and direct patient safety risk.

**Evidence from HAR:**
- Request: `POST https://api.telecare-consultatio.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-8f65`
- Query: `getResource(id: "R-2186") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-0a51"`, `ownerId: "other-user-8f650a51"`, `sensitiveField: "CONFIDENTIAL-8f650a51"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-8f650a51`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-186 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.12 | Mass assignment via object fields |
| HAR query | id: "R-2186" | Cross-tenant patient consultation lookup |
| HAR response | tenantId | tenant-0a51 returned to tenant-8f65 |
| HAR response | sensitiveField | CONFIDENTIAL-8f650a51 |
| HAR header | x-request-id | req-8f650a51 |

## Steps to Reproduce

### Step 1 — getResource mass assignment BOLA cross-tenant (HAR)
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8f65" \
  -d '{"query": "query { getResource(id: \"R-2186\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-0a51` consultation record including `CONFIDENTIAL-8f650a51`. **Secure:** FORBIDDEN — only `tenant-8f65` records accessible.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip all privileged/tenant-scoped fields (`ownerId`, `tenantId`) from client-supplied input objects.
3. PHI fields must not be returned unless explicit consent is verified via audit log.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
