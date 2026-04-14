# Analysis Explanation
**System analysed:** StreamCore VOD Platform — GQL-0169 (Media / VOD)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 5.1: `getResource` auth-bypass injection — no tenancy check.
2. HAR: `tenant-613b` queries `R-2169` → `tenant-9c08`: `CONFIDENTIAL-613b9c08`, `req-613b9c08`.
3. Media/VOD: licensed content libraries, DRM configs, subscriber data.

## Consistency Guard
Attacker: `tenant-613b`. Victim: `tenant-9c08`. Resource: `R-2169`. Sensitive: `CONFIDENTIAL-613b9c08`. ownerId: `other-user-613b9c08`. Request: `req-613b9c08`. All from this folder only.
