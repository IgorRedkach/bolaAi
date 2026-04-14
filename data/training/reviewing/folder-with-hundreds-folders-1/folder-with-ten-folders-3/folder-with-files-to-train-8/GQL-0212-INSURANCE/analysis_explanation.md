# Analysis Explanation
**System analysed:** ClaimsFlow Underwriting API — GQL-0212 (Insurance / Underwriting)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-212: `getClaim`/`listClaims` resolver lacks `tenantId` ownership check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 4.2: Integrity — persistence poisoning via lifecycle claim actions across tenant boundaries.
3. HAR: `tenant-442a` queries `listClaims(tenantId: "tenant-22b0")` → `tenant-22b0` claims: `CONFIDENTIAL-442a22b0`, `req-442a22b0`.
4. Insurance domain: claims data — insurance fraud and actuarial data poisoning.

## Consistency Guard
Attacker: `tenant-442a`. Victim: `tenant-22b0`. Claim: `C-2212`. Sensitive: `CONFIDENTIAL-442a22b0`. ownerId: `other-user-442a22b0`. Request: `req-442a22b0`. All from this folder only.
