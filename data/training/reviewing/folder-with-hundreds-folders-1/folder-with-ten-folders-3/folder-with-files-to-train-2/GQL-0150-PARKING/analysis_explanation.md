# Analysis Explanation
**System analysed:** ParkIQ Management API — GQL-0150 (Parking / Smart City)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 7.1: `bulkIntersectionLookup` exposes operational PII cross-tenant without tenancy guard.
2. HAR: `tenant-f1c6` queries `I-2150, I-1150, I-3150` → `tenant-ef42` data: `CONFIDENTIAL-f1c6ef42`, `req-f1c6ef42`.
3. Smart Parking: plate records, payment data, violation history — citizen PII.

## Consistency Guard
Attacker: `tenant-f1c6`. Victim: `tenant-ef42`. Resources: `I-2150, I-1150, I-3150`. Sensitive: `CONFIDENTIAL-f1c6ef42`. ownerId: `other-user-f1c6ef42`. Request: `req-f1c6ef42`. All from this folder only.
