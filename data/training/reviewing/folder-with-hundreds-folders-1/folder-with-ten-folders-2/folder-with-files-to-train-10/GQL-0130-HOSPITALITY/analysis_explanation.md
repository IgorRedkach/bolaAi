# Analysis Explanation
**System analysed:** StayPro Property API — GQL-0130 (Hospitality / Hotel PMS)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.1: `bulkResourceLookup` accepts arbitrary IDs — ID swap pattern, no tenancy guard.
2. HAR: `tenant-d2d4` queries `R-2130, R-1130, R-3130` → `tenant-e655` data: `CONFIDENTIAL-d2d4e655`, `req-d2d4e655`.
3. Hospitality: guest reservations, room assignments — consumer PII and GDPR risk.

## Consistency Guard
Attacker: `tenant-d2d4`. Victim: `tenant-e655`. Resources: `R-2130, R-1130, R-3130`. Sensitive: `CONFIDENTIAL-d2d4e655`. ownerId: `other-user-d2d4e655`. Request: `req-d2d4e655`. All from this folder only.
