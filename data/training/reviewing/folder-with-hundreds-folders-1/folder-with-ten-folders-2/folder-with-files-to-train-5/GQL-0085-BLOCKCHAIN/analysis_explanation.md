# Analysis Explanation
**System analysed:** ChainVault DeFi API — GQL-0085 (Blockchain / DeFi)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 9.1 (GraphQL single endpoint vulnerabilities — platform). All mutations share one endpoint with no per-operation authorization.
2. HAR: `updateResource(id: "R-2085", input: {status: "approved", ownerId: "attacker-9829a9b2"})` from `tenant-9829`. Response `tenant-a9b2`: `CONFIDENTIAL-9829a9b2`. `x-request-id: req-9829a9b2`.
3. Pattern 9.1 angle: `deleteResource` also available at same endpoint — second reproduction step shows delete exposure without per-operation auth.
4. DeFi domain: `ownerId` poisoning on financial vault has direct fund misappropriation potential.

## Consistency Guard
Tenant IDs: `tenant-9829`, `tenant-a9b2`. Resource: `R-2085`. Attacker ownerId injected: `attacker-9829a9b2`. Leaked: `CONFIDENTIAL-9829a9b2`. Request: `req-9829a9b2`. All from this folder only.
