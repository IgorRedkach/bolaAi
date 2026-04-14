# Expected Response

## System
- Domain: Cloud IAM / Identity Provider
- System: VaultGuard IAM API
- Example ID: GQL-0144

## Priority Findings

### Finding 1: Cloud IAM — Client-Assumed Authority via Bulk Lookup Exposes Cross-Tenant Identity Credentials (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §5.0 (Pattern 3.1 — client-assumed authority): The IAM API was designed assuming clients only request resources they own; however, no server-side ownership verification exists. An attacker from `tenant-bef7` queried `bulkResourceLookup(ids: ["R-2144", "R-1144", "R-3144"])` and received IAM identity data belonging to `tenant-807c`, including `CONFIDENTIAL-bef7807c`. In Cloud IAM, unauthorized access to identity and credential records enables privilege escalation, credential theft, and full tenant compromise.

**Evidence from HAR:**
- Request: `POST https://api.vaultguard-iam-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-bef7`
- Query: `bulkResourceLookup(ids: ["R-2144", "R-1144", "R-3144"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-807c"`, `ownerId: "other-user-bef7807c"`, `sensitiveField: "CONFIDENTIAL-bef7807c"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-bef7807c`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority, no server verify |
| HAR request | ids array | R-2144, R-1144, R-3144 (cross-tenant) |
| HAR response | tenantId | tenant-807c IAM data returned |
| HAR response | sensitiveField | CONFIDENTIAL-bef7807c |

## Steps to Reproduce

### Step 1 — Bulk IAM resource lookup (HAR)
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-bef7" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2144\", \"R-1144\", \"R-3144\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-807c` IAM credential data returned. **Secure:** Only `tenant-bef7` data or FORBIDDEN.

## Remediation
1. Server must verify ownership; never trust client-supplied IDs.
2. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
3. Credential fields must be masked in all query responses; use token references.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
