# Analysis Explanation
**System analysed:** LearnPath Assessment Platform — GQL-0066 (Education / EdTech LMS)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 10.5 (draft/non-published resource access — single-user). Resolver does not check tenantId, exposing draft assets.
2. §4.0 RISK-GQL-066: `getResource` fetches by `resourceId` only — no tenantId match.
3. Domain: EdTech — `sensitiveField` likely contains assessment answers or draft course content.
4. HAR: `getResource(id: "R-2066")` from `tenant-3ab7`. Response `tenant-5984`: `CONFIDENTIAL-3ab75984`. `x-request-id: req-3ab75984`.

## Consistency Guard
Tenant IDs: `tenant-3ab7`, `tenant-5984`. Resource: `R-2066`. ownerId: `other-user-3ab75984`. Leaked: `CONFIDENTIAL-3ab75984`. Request: `req-3ab75984`. All from this folder only.
