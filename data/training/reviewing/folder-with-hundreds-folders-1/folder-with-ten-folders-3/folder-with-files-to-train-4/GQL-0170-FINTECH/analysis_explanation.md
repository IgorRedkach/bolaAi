# Analysis Explanation
**System analysed:** PayBridge Transaction API — GQL-0170 (FinTech / Payments)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 5.2: `listResources` traversal with client tenantId — resolver injection.
2. HAR: `tenant-ce72` passes `tenantId: "tenant-439d"` → `CONFIDENTIAL-ce72439d`, `req-ce72439d`.
3. FinTech/Payments: transaction records, fraud scoring — PCI-DSS and financial fraud risk.

## Consistency Guard
Attacker: `tenant-ce72`. Victim: `tenant-439d`. Sensitive: `CONFIDENTIAL-ce72439d`. ownerId: `other-user-ce72439d`. Request: `req-ce72439d`. All from this folder only.
