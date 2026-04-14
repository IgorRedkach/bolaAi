# Analysis Explanation
**System analysed:** VitalTrack Health API — GQL-0131 (Fitness / Wearables)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.2: `getResource` accepts `resourceId` without tenancy check — parameter escalation beyond own session.
2. HAR: `tenant-e728` queries `R-2131` → `tenant-272e` health data: `CONFIDENTIAL-e728272e`, `req-e728272e`.
3. Fitness/Wearables: biometric health data — HIPAA/GDPR-sensitive personal health information.

## Consistency Guard
Attacker: `tenant-e728`. Victim: `tenant-272e`. Resource: `R-2131`. Sensitive: `CONFIDENTIAL-e728272e`. ownerId: `other-user-e728272e`. Request: `req-e728272e`. All from this folder only.
