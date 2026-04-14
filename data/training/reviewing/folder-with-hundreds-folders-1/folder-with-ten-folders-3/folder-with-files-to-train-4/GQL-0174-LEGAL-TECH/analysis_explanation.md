# Analysis Explanation
**System analysed:** LexVault eDiscovery API — GQL-0174 (Legal Tech / eDiscovery)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.1: `getResource` ID swap — no ownership verification.
2. HAR: `tenant-e8ba` queries `R-2174` → `tenant-f6ce`: `CONFIDENTIAL-e8baf6ce`, `req-e8baf6ce`.
3. Legal Tech: attorney-client privilege, evidence files, legal hold — privilege violation risk.

## Consistency Guard
Attacker: `tenant-e8ba`. Victim: `tenant-f6ce`. Resource: `R-2174`. Sensitive: `CONFIDENTIAL-e8baf6ce`. ownerId: `other-user-e8baf6ce`. Request: `req-e8baf6ce`. All from this folder only.
