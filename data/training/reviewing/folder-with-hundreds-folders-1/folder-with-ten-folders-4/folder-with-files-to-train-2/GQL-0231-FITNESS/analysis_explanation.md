# Analysis Explanation
**System analysed:** VitalTrack Health API — GQL-0231 (Fitness / Wearables)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-231: `getResource` resolver fetches by `resourceId` only — no `tenantId` check.
2. §5.0 Pattern 2.2: BAC — metadata/attribute side-channel; `sensitiveField` leaks health telemetry without access control enforcement.
3. HAR: `tenant-17c6` queries `getResource(id: "R-2231")` → `tenant-8ba0` health data: `CONFIDENTIAL-17c68ba0`, `req-17c68ba0`.
4. Fitness/Wearables domain: biometric data, heart rate, sleep patterns — PHI under HIPAA/GDPR if linked to identifiable users; the `sensitiveField` attribute is the side-channel vector.

## Consistency Guard
Attacker: `tenant-17c6`. Victim: `tenant-8ba0`. Resource: `R-2231`. Sensitive: `CONFIDENTIAL-17c68ba0`. ownerId: `other-user-17c68ba0`. Request: `req-17c68ba0`. All from this folder only.
