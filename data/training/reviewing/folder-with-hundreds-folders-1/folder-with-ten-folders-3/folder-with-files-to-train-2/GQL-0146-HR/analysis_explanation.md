# Analysis Explanation
**System analysed:** WageFlow Payroll API — GQL-0146 (HR / Payroll Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 4.2: `listResources` accepts `tenantId` — persistence poisoning via lifecycle.
2. HAR: `tenant-f056` passes `tenantId: "tenant-9ce9"` → payroll data: `CONFIDENTIAL-f0569ce9`, `req-f0569ce9`.
3. HR/Payroll: employee salaries, tax data, bank accounts — financial and identity theft risk.

## Consistency Guard
Attacker: `tenant-f056`. Victim: `tenant-9ce9`. Sensitive: `CONFIDENTIAL-f0569ce9`. ownerId: `other-user-f0569ce9`. Request: `req-f0569ce9`. All from this folder only.
