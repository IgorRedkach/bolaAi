# Analysis Explanation
**System analysed:** ChainVault DeFi API — GQL-0235 (Blockchain / DeFi)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-235: `listResources` accepts client-supplied `tenantId` — not validated against JWT.
2. §5.0 Pattern 5.1: Injection — authorization-bypass injection; attacker injects victim's `tenantId` directly into the authorization-scoping parameter.
3. HAR: `tenant-d9b1` calls `listResources(tenantId: "tenant-c321")` → `tenant-c321` DeFi data: `CONFIDENTIAL-d9b1c321`, `req-d9b1c321`.
4. Blockchain/DeFi domain: wallet addresses, token balances, transaction histories — financial identity data; unauthorized access is financial surveillance.

## Consistency Guard
Attacker: `tenant-d9b1`. Victim: `tenant-c321`. Sensitive: `CONFIDENTIAL-d9b1c321`. ownerId: `other-user-d9b1c321`. Request: `req-d9b1c321`. All from this folder only.
