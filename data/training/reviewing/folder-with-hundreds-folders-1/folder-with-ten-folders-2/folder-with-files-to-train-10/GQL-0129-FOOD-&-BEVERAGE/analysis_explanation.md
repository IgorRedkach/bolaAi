# Analysis Explanation
**System analysed:** TraceOrigin Supply API — GQL-0129 (Food & Beverage / FMCG)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 9.1: Single GraphQL endpoint, no per-operation tenant isolation — cross-tenant access via `getResource`.
2. HAR: `tenant-edc4` queries `R-2129` → `tenant-00d9` data: `CONFIDENTIAL-edc400d9`, `req-edc400d9`.
3. Food/FMCG: origin traceability records, supplier identity — food safety and supply chain integrity.

## Consistency Guard
Attacker: `tenant-edc4`. Victim: `tenant-00d9`. Resource: `R-2129`. Sensitive: `CONFIDENTIAL-edc400d9`. ownerId: `other-user-edc400d9`. Request: `req-edc400d9`. All from this folder only.
