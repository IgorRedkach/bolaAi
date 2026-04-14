# Analysis Explanation
**System analysed:** Horizon Social Graph API — GQL-0161 (Social Media / Identity Graph)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.8: Predictable post IDs + no ownership check enable enumeration BOLA.
2. HAR: `tenant-62dc` mutates `P-2161` with `ownerId: "attacker-62dc7f5b"` → `tenant-7f5b`: `CONFIDENTIAL-62dc7f5b`, `req-62dc7f5b`.
3. Social Media: user content manipulation, identity graph data.

## Consistency Guard
Attacker: `tenant-62dc`. Victim: `tenant-7f5b`. Resource: `P-2161`. Sensitive: `CONFIDENTIAL-62dc7f5b`. ownerId input: `attacker-62dc7f5b`. Request: `req-62dc7f5b`. All from this folder only.
