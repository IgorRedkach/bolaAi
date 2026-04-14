# Analysis Explanation
**System analysed:** RailCore Operations API — GQL-0188 (Railway / Critical Rail Infrastructure)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-188: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 3.1: Insecure Design — client-assumed authority; resolver trusts client-supplied identity context.
3. HAR: `tenant-6ab2` queries `getResource(id: "R-2188")` → `tenant-df08` rail operations record: `CONFIDENTIAL-6ab2df08`, `req-6ab2df08`.
4. Railway domain: signalling, scheduling, operational data — direct public safety risk.

## Consistency Guard
Attacker: `tenant-6ab2`. Victim: `tenant-df08`. Resource: `R-2188`. Sensitive: `CONFIDENTIAL-6ab2df08`. ownerId: `other-user-6ab2df08`. Request: `req-6ab2df08`. All from this folder only.
