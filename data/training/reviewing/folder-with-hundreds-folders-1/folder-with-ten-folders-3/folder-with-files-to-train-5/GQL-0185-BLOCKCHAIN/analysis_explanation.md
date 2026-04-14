# Analysis Explanation
**System analysed:** ChainVault DeFi API — GQL-0185 (Blockchain / Decentralized Finance)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-185: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.10: BOLA — cross-service identity propagation drift; caller-supplied `tenantId` not re-validated across microservices.
3. HAR: `tenant-c1b7` queries `listResources(tenantId: "tenant-eea1")` → `tenant-eea1` DeFi vault records: `CONFIDENTIAL-c1b7eea1`, `req-c1b7eea1`.
4. DeFi domain: vault balances, transaction history, smart contract state — critical financial security incident.

## Consistency Guard
Attacker: `tenant-c1b7`. Victim: `tenant-eea1`. Resource: `R-2185`. Sensitive: `CONFIDENTIAL-c1b7eea1`. ownerId: `other-user-c1b7eea1`. Request: `req-c1b7eea1`. All from this folder only.
