# Analysis Explanation
**System analysed:** RailCore Operations API — GQL-0238 (Railway / SCADA)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-238: `updateResource` resolver lacks `tenantId` ownership check.
2. §5.0 Pattern 7.1: Logging Failures — operational PII/PHI leakage; sensitive data returned in API response is also captured in API gateway logs, access logs, and audit trails.
3. HAR: `tenant-fd03` issues `updateResource(id: "R-2238", ...)` → `tenant-0f60` SCADA data: `CONFIDENTIAL-fd030f60`, `req-fd030f60`.
4. Railway/SCADA domain: signal states, track occupancy, control room configurations — critical national infrastructure; NIS2/IEC 62443 controls apply.

## Consistency Guard
Attacker: `tenant-fd03`. Victim: `tenant-0f60`. Resource: `R-2238`. Sensitive: `CONFIDENTIAL-fd030f60`. ownerId: `other-user-fd030f60`. Request: `req-fd030f60`. All from this folder only.
