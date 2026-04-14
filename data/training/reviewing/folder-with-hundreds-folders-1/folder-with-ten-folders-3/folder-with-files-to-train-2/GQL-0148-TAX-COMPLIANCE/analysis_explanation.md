# Analysis Explanation
**System analysed:** TaxGrid Compliance API — GQL-0148 (Tax Compliance / RegTech)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 5.2: `getResource` traverses compliance graph without tenancy at each node.
2. HAR: `tenant-e190` queries `R-2148` → `tenant-a21a` data: `CONFIDENTIAL-e190a21a`, `req-e190a21a`.
3. Tax Compliance: filed returns, audit history, regulatory submissions — financial disclosure leak.

## Consistency Guard
Attacker: `tenant-e190`. Victim: `tenant-a21a`. Resource: `R-2148`. Sensitive: `CONFIDENTIAL-e190a21a`. ownerId: `other-user-e190a21a`. Request: `req-e190a21a`. All from this folder only.
