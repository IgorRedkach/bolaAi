# Analysis Explanation
**System analysed:** ClaimsFlow Underwriting API — GQL-0112 (Insurance / Claims Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-112: `getClaim` fetches by `claimId` only, enabling Pattern 1.2 (related linked resources BOLA).
2. HAR: `tenant-5ced` queries `C-2112` → `tenant-70ad` data: `CONFIDENTIAL-5ced70ad`, `req-5ced70ad`.
3. Insurance: policy, settlement, medical evidence — high-sensitivity claims data.

## Consistency Guard
Attacker: `tenant-5ced`. Victim: `tenant-70ad`. Resource: `C-2112`. Sensitive: `CONFIDENTIAL-5ced70ad`. ownerId: `other-user-5ced70ad`. Request: `req-5ced70ad`. All from this folder only.
