# Analysis Explanation
**System analysed:** TraceOrigin Supply API — GQL-0229 (Food & Beverage / FMCG)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-229: Resolver fetches by `resourceId`/`tenantId` arg only — no JWT cross-check.
2. §5.0 Pattern 1.10: BOLA — cross-service identity propagation drift; authenticated `tenantId` from JWT not enforced in downstream resolver logic.
3. HAR: `tenant-cf0e` calls `listResources(tenantId: "tenant-883a")` → `tenant-883a` supply chain data returned: `CONFIDENTIAL-cf0e883a`, `req-cf0e883a`.
4. Food & Beverage/Blockchain domain: supply chain provenance, ingredient sourcing, recall data — competitor espionage and food safety risk.
5. Identity drift: JWT says `tenant-cf0e` but resolver uses client arg `tenant-883a` without re-validation.

## Consistency Guard
Attacker: `tenant-cf0e`. Victim: `tenant-883a`. Sensitive: `CONFIDENTIAL-cf0e883a`. ownerId: `other-user-cf0e883a`. Request: `req-cf0e883a`. All from this folder only.
