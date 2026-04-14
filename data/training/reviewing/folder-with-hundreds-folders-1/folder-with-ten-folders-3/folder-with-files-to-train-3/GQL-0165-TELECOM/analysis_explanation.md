# Analysis Explanation
**System analysed:** SpectreNet Policy Control — GQL-0165 (Telecom / 5G Core)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 2.2: `getResource` exposes `internalNotes` metadata — BAC side-channel.
2. HAR: `tenant-1ebc` queries `R-2165` → `tenant-06ff` policy: `CONFIDENTIAL-1ebc06ff`, `internalNotes: "Internal data exposed"`, `req-1ebc06ff`.
3. Telecom/5G: QoS rules, network slice config — critical infrastructure.

## Consistency Guard
Attacker: `tenant-1ebc`. Victim: `tenant-06ff`. Resource: `R-2165`. Sensitive: `CONFIDENTIAL-1ebc06ff`. ownerId: `other-user-1ebc06ff`. Request: `req-1ebc06ff`. All from this folder only.
