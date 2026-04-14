# Analysis Explanation
**System analysed:** AeroOps Flight Management — GQL-0237 (Aviation / Flight Ops)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-237: `updateResource` resolver lacks `tenantId` ownership check.
2. §5.0 Pattern 6.1: Misconfiguration — schema/relationship over-exposure; mutation response type includes full sensitive relationship fields (`sensitiveField`, `internalNotes`) that should not be returned in mutation responses.
3. HAR: `tenant-1fa8` issues `updateResource(id: "R-2237", ...)` → `tenant-5324` flight data: `CONFIDENTIAL-1fa85324`, `req-1fa85324`.
4. Aviation domain: flight plans, crew assignments, operational parameters — safety-critical; ICAO security regulations apply.

## Consistency Guard
Attacker: `tenant-1fa8`. Victim: `tenant-5324`. Resource: `R-2237`. Sensitive: `CONFIDENTIAL-1fa85324`. ownerId: `other-user-1fa85324`. Request: `req-1fa85324`. All from this folder only.
