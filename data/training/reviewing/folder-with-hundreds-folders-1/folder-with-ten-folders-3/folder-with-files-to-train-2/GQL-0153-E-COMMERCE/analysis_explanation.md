# Analysis Explanation
**System analysed:** ShopGrid Marketplace API — GQL-0153 (E-Commerce / Marketplace)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.2: `getOrder` accepts `orderId` without tenancy check — parameter escalation.
2. HAR: `tenant-7b57` queries `O-2153` → `tenant-566f` order: `CONFIDENTIAL-7b57566f`, `req-7b57566f`.
3. E-Commerce: payment method, shipping address, purchase history — PCI-DSS and consumer PII risk.

## Consistency Guard
Attacker: `tenant-7b57`. Victim: `tenant-566f`. Resource: `O-2153`. Sensitive: `CONFIDENTIAL-7b57566f`. ownerId: `other-user-7b57566f`. Request: `req-7b57566f`. All from this folder only.
