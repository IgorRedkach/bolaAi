# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: GQL-0153

## Priority Findings

### Finding 1: E-Commerce — Parameter Escalation Exposes Cross-Tenant Order Data (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §5.0 (Pattern 10.2 — parameter escalation): The `getOrder` resolver accepts `orderId` directly without verifying that the order belongs to the caller's tenant, enabling session scope escalation. An attacker from `tenant-7b57` queried `getOrder(id: "O-2153")` and received marketplace order data belonging to `tenant-566f`, including `CONFIDENTIAL-7b57566f`. In E-Commerce / Marketplace, this exposes customer order details, payment method data, shipping addresses, and purchase history.

**Evidence from HAR:**
- Request: `POST https://api.shopgrid-marketplace.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-7b57`
- Query: `getOrder(id: "O-2153") { orderId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-566f"`, `ownerId: "other-user-7b57566f"`, `sensitiveField: "CONFIDENTIAL-7b57566f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-7b57566f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.2 | getOrder parameter escalation |
| HAR request | x-tenant-id | Attacker tenant-7b57 |
| HAR response | tenantId | Cross-tenant order data tenant-566f |
| HAR response | sensitiveField | CONFIDENTIAL-7b57566f |

## Steps to Reproduce

### Step 1 — getOrder with escalated order ID (HAR)
```bash
curl -s -X POST https://api.shopgrid-marketplace.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-7b57" \
  -d '{"query": "query { getOrder(id: \"O-2153\") { orderId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-566f` order data returned. **Secure:** FORBIDDEN.

## Remediation
1. `getOrder` resolver: `WHERE order_id=$id AND tenant_id=$jwt.tenantId`.
2. Payment method fields masked; only last 4 digits visible.
3. Redis cache key: `order:{tenantId}:{orderId}`.
