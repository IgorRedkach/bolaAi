# Expected Response

## System
- **Domain:** E-Commerce / Marketplace
- **System:** ShopGrid Marketplace API
- **Example ID:** GQL-0203

## Priority Findings

### Finding 1: E-Commerce Marketplace — BOLA Write Operation via listOrders Exposes Cross-Tenant Order Data (Pattern 1.6)
**Severity:** High
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-203): The `getOrder` resolver fetches by `orderId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.6 — write operations without ownership check): the `listOrders` endpoint accepts a caller-supplied `tenantId` without JWT validation, allowing cross-tenant order data access via a write-path query. An attacker from `tenant-df98` queried `listOrders(tenantId: "tenant-20cf")` and received order records belonging to `tenant-20cf`, including `CONFIDENTIAL-df9820cf`. In E-Commerce / Marketplace, unauthorized access to order data, customer shipping addresses, and payment records enables fraud, competitor intelligence, and privacy violation.

**Evidence from HAR:**
- Request: `POST https://api.shopgrid-marketplace.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-df98`
- Query: `listOrders(tenantId: "tenant-20cf") { orderId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-20cf"`, `ownerId: "other-user-df9820cf"`, `sensitiveField: "CONFIDENTIAL-df9820cf"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-df9820cf`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-203 | getOrder resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.6 | Write operation accepts caller-supplied tenantId |
| HAR query | tenantId: "tenant-20cf" | Injected cross-tenant order filter |
| HAR response | tenantId | tenant-20cf returned to tenant-df98 |
| HAR response | sensitiveField | CONFIDENTIAL-df9820cf |
| HAR header | x-request-id | req-df9820cf |

## Steps to Reproduce

### Step 1 — listOrders write operation BOLA cross-tenant (HAR)
```bash
curl -s -X POST https://api.shopgrid-marketplace.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-df98" \
  -d '{"query": "query { listOrders(tenantId: \"tenant-20cf\") { orderId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-20cf` order records including `CONFIDENTIAL-df9820cf`. **Secure:** FORBIDDEN — `tenantId` from JWT; only `tenant-df98` orders returned.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Write operations must validate `WHERE order_id = $id AND tenant_id = $jwt.tenantId`.
3. Redis cache key: `order:{tenantId}:{orderId}`.
