# Analysis Explanation
**System analysed:** TeleCare Consultation API — GQL-0236 (Telemedicine / Remote Care)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-236: `updateResource` resolver fetches by `resourceId` only — no `tenantId` check.
2. §5.0 Pattern 5.2: Injection — resolver/graph traversal injection; attacker traverses through the resolver boundary to a cross-tenant resource and injects via mutation.
3. HAR: `tenant-ef0e` issues `updateResource(id: "R-2236", input: {status: "approved", ownerId: "attacker-ef0e64a5"})` → `tenant-64a5` patient data: `CONFIDENTIAL-ef0e64a5`, `req-ef0e64a5`.
4. Telemedicine domain: consultation records, diagnoses, prescriptions — PHI under HIPAA; cross-tenant write is a notifiable breach.

## Consistency Guard
Attacker: `tenant-ef0e`. Victim: `tenant-64a5`. Resource: `R-2236`. Sensitive: `CONFIDENTIAL-ef0e64a5`. ownerId: `other-user-ef0e64a5`. Request: `req-ef0e64a5`. All from this folder only.
