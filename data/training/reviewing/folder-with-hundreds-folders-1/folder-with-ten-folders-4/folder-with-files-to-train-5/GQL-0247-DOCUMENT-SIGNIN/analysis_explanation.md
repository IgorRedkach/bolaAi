# Analysis Explanation
**System analysed:** SignFlow eSign Platform — GQL-0247 (Document Signing / eSign)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-247: `updateResource` lacks `tenantId` ownership check for write operation.
2. §5.0 Pattern 1.6: BOLA — write operation without ownership check; attacker approves and attempts to hijack victim's eSign document.
3. HAR: `tenant-5317` issues `updateResource(id: "R-2247", input: {status: "approved", ownerId: "attacker-5317cfb4"})` → `tenant-cfb4` document: `CONFIDENTIAL-5317cfb4`, `req-5317cfb4`.
4. eSign domain: legally binding documents — forged approval is fraud.

## Consistency Guard
Attacker: `tenant-5317`. Victim: `tenant-cfb4`. Resource: `R-2247`. Sensitive: `CONFIDENTIAL-5317cfb4`. ownerId: `other-user-5317cfb4`. Request: `req-5317cfb4`. All from this folder only.
