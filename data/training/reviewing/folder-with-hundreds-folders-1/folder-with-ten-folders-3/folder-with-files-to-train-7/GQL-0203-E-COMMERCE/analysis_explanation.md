# Analysis Explanation
**System analysed:** ShopGrid Marketplace API — GQL-0203 (E-Commerce / Marketplace)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-203: `getOrder`/`listOrders` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 1.6: BOLA — write operations accept caller-supplied `tenantId` filter without JWT validation.
3. HAR: `tenant-df98` queries `listOrders(tenantId: "tenant-20cf")` → `tenant-20cf` order records: `CONFIDENTIAL-df9820cf`, `req-df9820cf`.
4. E-Commerce domain: order data, shipping addresses, payment records — fraud and privacy violation.

## Consistency Guard
Attacker: `tenant-df98`. Victim: `tenant-20cf`. Order: `O-2203`. Sensitive: `CONFIDENTIAL-df9820cf`. ownerId: `other-user-df9820cf`. Request: `req-df9820cf`. All from this folder only.
