# Analysis Explanation
**System analysed:** WageFlow Payroll API — GQL-0096 (HR / Payroll)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.9 (batch/bulk lookup — BOLA). `listResources(tenantId:)` enables batch enumeration of payroll records.
2. HAR: `listResources(tenantId: "tenant-fce5")` from `tenant-f86b`. Response `tenant-fce5`: `CONFIDENTIAL-f86bfce5`. `x-request-id: req-f86bfce5`.
3. HR domain: payroll data (salary, tax ID, bank references) = highest-sensitivity employment PII.

## Consistency Guard
Tenant IDs: `tenant-f86b`, `tenant-fce5`. ownerId: `other-user-f86bfce5`. Leaked: `CONFIDENTIAL-f86bfce5`. Request: `req-f86bfce5`. All from this folder only.
