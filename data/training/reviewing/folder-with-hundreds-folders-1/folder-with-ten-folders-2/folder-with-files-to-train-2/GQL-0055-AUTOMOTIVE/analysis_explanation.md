# Analysis Explanation

**System analysed:** AetherDrive V2X Telematics — GQL-0055 (Automotive / Connected Car)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 2.2 (metadata/attribute side-channel). "`listResources` exposes partial data even for unauthorised objects, leaking the existence and metadata of records the user should not know about."
2. **Read §3.0** — Generic `Resource`/`ResourceData` types with `listResources(tenantId: ID)`.
3. **Read §4.0** — RISK-GQL-055 + bulkResourceLookup no per-ID filter. Cache by `resourceId` only.
4. **Read HAR** — `updateResource(id: "R-2055", input: {status: "approved", ownerId: "attacker-58a5c622"})`. Response `tenant-c622`: `CONFIDENTIAL-58a5c622`. `x-request-id: req-58a5c622`.
5. **Two attack vectors** — Step 1: `listResources` metadata side-channel (§5.0). Step 2: HAR write BOLA. Both grounded in context.txt only.

## Consistency Guard
- Tenant IDs: `tenant-58a5`, `tenant-c622`. Resource: `R-2055`. Injected ownerId: `attacker-58a5c622`. Leaked: `CONFIDENTIAL-58a5c622`, `other-user-58a5c622`. Request ID: `req-58a5c622`. All from this folder only.
