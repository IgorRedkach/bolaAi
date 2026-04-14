## Analysis reasoning

I reviewed the RailGrid Signaling and Operations Management (ROMS) specification (v15.0.3) and the accompanying HAR trace as engineering artifacts in a critical-infrastructure OT context.

1. **Zone-scoped RBAC boundary mapping**: from sections 3.1 and 5.0 I established that every rail switch has a `zone_id` column in `rail_switches` and every operator has a `zone_id` in `rail_operators`. The security contract is: an operator may only actuate switches in their assigned zone. The attacker (`user_yard_1004`, `ZONE-YARD-A`) and the target asset (`SW-MAIN-001`, `ZONE-MAIN-LINE-C`) are in different zones.

2. **Multi-step workflow enforcement gap**: section 3.0 states zone check occurs only at the LOCK step (step 1). The `actuate_switch` view (section 6.0) shows the zone check is commented out — the only active check at EXECUTE is lock ownership, not zone boundary. This is the unsecured workflow gap (Pattern 3.5): passing step 1 confers no implicit authorisation for step 3.

3. **Fail-open identification (RISK-RAIL-007)**: section 4.0 documents the refactoring that introduced the fail-open default. The view code confirms: `if not ptc_verified_header: log.warning(...)` then falls through to `plc_service.send_command()`. The HAR response `"warning": "PTC check header was missing in request."` alongside HTTP 200 is direct runtime proof of the fail-open path executing.

4. **HAR evidence grounding**: the request headers array contains no `X-PTC-Verified` entry, confirming intentional omission. The `x-plc-command-ack: ACK_SW_001_RVR` response header is the PLC-layer acknowledgement that the REVERSE command was physically dispatched to switch SW-MAIN-001. The 780 ms latency is consistent with a PLC round-trip command (section analysis note: OT command latency is higher than IT API calls).

5. **Device ID manipulation confirmation**: the URI `/api/v3/switches/SW-MAIN-001/actuate` substitutes the attacker's authorised asset (`SW-YARD-005`, shown in section 7.1 as the safe payload) with the high-consequence target (`SW-MAIN-001`). The system never validates that the switch ID in the URI is within the caller's zone at the execute step.

6. **Reproduction path**: two-step sequence mirrors the real workflow — first LOCK (which passes the weak initial check), then ACTUATE with omitted PTC header. Both steps use only endpoints, IDs, headers, and JWT claims visible in the context.
