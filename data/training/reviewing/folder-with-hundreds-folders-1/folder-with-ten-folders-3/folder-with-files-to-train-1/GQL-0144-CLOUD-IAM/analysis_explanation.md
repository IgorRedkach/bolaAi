# Analysis Explanation
**System analysed:** VaultGuard IAM API — GQL-0144 (Cloud IAM / Identity Provider)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 3.1: IAM API designed with client-assumed authority — no server-side ownership verification.
2. HAR: `tenant-bef7` queries `R-2144, R-1144, R-3144` → `tenant-807c` IAM data: `CONFIDENTIAL-bef7807c`, `req-bef7807c`.
3. Cloud IAM: identity credentials — privilege escalation and tenant compromise risk.

## Consistency Guard
Attacker: `tenant-bef7`. Victim: `tenant-807c`. Resources: `R-2144, R-1144, R-3144`. Sensitive: `CONFIDENTIAL-bef7807c`. ownerId: `other-user-bef7807c`. Request: `req-bef7807c`. All from this folder only.
