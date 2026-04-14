# Analysis Explanation
**System analysed:** WageFlow Payroll API — GQL-0246 (HR / Payroll Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-246: `bulkResourceLookup` lacks per-ID tenancy check.
2. §5.0 Pattern 1.5: BOLA — multi-tenant/cross-tenant; bulk access to cross-tenant payroll records.
3. HAR: `tenant-b3dd` calls `bulkResourceLookup(ids: ["R-2246","R-1246","R-3246"])` → `tenant-0e51` payroll data: `CONFIDENTIAL-b3dd0e51`, `req-b3dd0e51`.
4. HR/Payroll domain: employee salary, tax records, PII — GDPR and employment law.

## Consistency Guard
Attacker: `tenant-b3dd`. Victim: `tenant-0e51`. Resources: `R-2246`, `R-1246`, `R-3246`. Sensitive: `CONFIDENTIAL-b3dd0e51`. ownerId: `other-user-b3dd0e51`. Request: `req-b3dd0e51`. All from this folder only.
