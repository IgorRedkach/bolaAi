# Analysis Explanation
**System analysed:** NeoBuild BAS Platform — GQL-0143 (Smart Home / Building Automation)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 2.2: `getResource` exposes `internalNotes` metadata — BAC side-channel.
2. HAR: `tenant-0db4` queries `R-2143` → `tenant-d181` data: `CONFIDENTIAL-0db4d181`, `internalNotes: "Internal data exposed"`, `req-0db4d181`.
3. Smart Home/BAS: HVAC, access control, occupancy — physical security and privacy risk.

## Consistency Guard
Attacker: `tenant-0db4`. Victim: `tenant-d181`. Resource: `R-2143`. Sensitive: `CONFIDENTIAL-0db4d181`. ownerId: `other-user-0db4d181`. Request: `req-0db4d181`. All from this folder only.
