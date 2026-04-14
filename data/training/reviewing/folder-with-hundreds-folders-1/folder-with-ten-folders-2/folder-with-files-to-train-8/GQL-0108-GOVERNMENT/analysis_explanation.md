# Analysis Explanation
**System analysed:** FirstResponse CAD Integration — GQL-0108 (Government / Public Safety)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.1: `listResources` accepts client-supplied `tenantId`, enabling ID swap.
2. HAR: attacker `tenant-0417` passes `tenantId: "tenant-8f38"` and receives `CONFIDENTIAL-04178f38`, `x-request-id: req-04178f38`.
3. Government/Public Safety: CAD dispatch records — officer safety risk.

## Consistency Guard
Attacker: `tenant-0417`. Victim: `tenant-8f38`. Sensitive: `CONFIDENTIAL-04178f38`. ownerId: `other-user-04178f38`. Request: `req-04178f38`. All from this folder only.
