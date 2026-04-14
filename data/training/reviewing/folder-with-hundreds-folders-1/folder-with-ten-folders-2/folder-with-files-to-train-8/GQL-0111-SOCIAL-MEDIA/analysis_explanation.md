# Analysis Explanation
**System analysed:** Horizon Social Graph API — GQL-0111 (Social Media / Identity Graph)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-111: `getPost` accepts `postId` without ownership check, enabling Pattern 1.1 (BOLA ID in path).
2. HAR: `tenant-93af` mutates `P-2111` with `ownerId: "attacker-93afd127"` → `tenant-d127` data: `CONFIDENTIAL-93afd127`, `req-93afd127`.
3. Social Media: identity graph data — unauthorized post mutation / identity takeover risk.

## Consistency Guard
Attacker: `tenant-93af`. Victim: `tenant-d127`. Resource: `P-2111`. Sensitive: `CONFIDENTIAL-93afd127`. ownerId input: `attacker-93afd127`. Request: `req-93afd127`. All from this folder only.
