# Analysis Explanation
**System analysed:** TeleCare Consultation API — GQL-0186 (Telemedicine / Remote Healthcare)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-186: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.12: BOLA — mass assignment via object fields; privileged fields not stripped from client input.
3. HAR: `tenant-8f65` queries `getResource(id: "R-2186")` → `tenant-0a51` consultation record: `CONFIDENTIAL-8f650a51`, `req-8f650a51`.
4. Telemedicine domain: patient consultations, diagnoses, prescriptions — HIPAA violation, patient safety risk.

## Consistency Guard
Attacker: `tenant-8f65`. Victim: `tenant-0a51`. Resource: `R-2186`. Sensitive: `CONFIDENTIAL-8f650a51`. ownerId: `other-user-8f650a51`. Request: `req-8f650a51`. All from this folder only.
