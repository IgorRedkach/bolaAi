# Analysis Explanation
**System analysed:** WageFlow Payroll API — GQL-0196 (HR / Payroll Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-196: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 10.1: Single-User — ID swap in own request bypasses ownership check.
3. HAR: `tenant-f17a` submits `updateResource(id: "R-2196", input: {ownerId: "attacker-f17a3569"})` → `tenant-3569` payroll record: `CONFIDENTIAL-f17a3569`, `req-f17a3569`.
4. HR/Payroll domain: salary records, tax data, employee compensation — GDPR/employment law violation.

## Consistency Guard
Attacker: `tenant-f17a`. Victim: `tenant-3569`. Resource: `R-2196`. Sensitive: `CONFIDENTIAL-f17a3569`. ownerId input: `attacker-f17a3569`. Request: `req-f17a3569`. All from this folder only.
