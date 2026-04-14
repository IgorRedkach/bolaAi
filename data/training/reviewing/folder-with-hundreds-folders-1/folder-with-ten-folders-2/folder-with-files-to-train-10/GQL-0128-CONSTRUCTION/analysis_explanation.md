# Analysis Explanation
**System analysed:** BuildCore BIM Collaboration — GQL-0128 (Construction / BIM Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 7.1: `bulkResourceLookup` leaks operational BIM data cross-tenant (no tenancy enforcement).
2. HAR: `tenant-2822` queries `R-2128, R-1128, R-3128` → `tenant-3c67` data: `CONFIDENTIAL-28223c67`, `req-28223c67`.
3. Construction/BIM: structural specs, subcontractor data — IP and safety compliance risk.

## Consistency Guard
Attacker: `tenant-2822`. Victim: `tenant-3c67`. Resources: `R-2128, R-1128, R-3128`. Sensitive: `CONFIDENTIAL-28223c67`. ownerId: `other-user-28223c67`. Request: `req-28223c67`. All from this folder only.
