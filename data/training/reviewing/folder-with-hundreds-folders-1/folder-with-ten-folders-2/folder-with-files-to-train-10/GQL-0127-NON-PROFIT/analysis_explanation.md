# Analysis Explanation
**System analysed:** GrantFlow CRM API — GQL-0127 (Non-Profit / Grant Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 6.1: Schema over-exposes relationship fields enabling cross-tenant traversal.
2. HAR: `tenant-4df6` queries `R-2127, R-1127, R-3127` → `tenant-7b03` data: `CONFIDENTIAL-4df67b03`, `req-4df67b03`.
3. Non-Profit/Grant: donor and beneficiary records — confidential funding data.

## Consistency Guard
Attacker: `tenant-4df6`. Victim: `tenant-7b03`. Resources: `R-2127, R-1127, R-3127`. Sensitive: `CONFIDENTIAL-4df67b03`. ownerId: `other-user-4df67b03`. Request: `req-4df67b03`. All from this folder only.
