## System

- System: ManuControl Robotics Fleet API v4.2.0
- Domain: INDUSTRIAL IOT (IIoT) / MANUFACTURING / OPERATIONAL TECHNOLOGY (OT)
- Risk ID: RISK-OT-601

## Findings

### 1. Critical Infrastructure Interface Exposure — PLC Control Service Reachable from Corporate Network (Pattern 2.5)

The Kubernetes Ingress Controller for the PLC Control Service was misconfigured with `host: ` and `path: /api/v1/robotics/`, exposing it to the entire corporate network (section 2.1). The service relies exclusively on network segmentation for trust — it performs no JWT validation and only reads an `X-Device-ID` header to select the target device (section 3.1). The Java controller confirms this:

```java
// VULNERABILITY 2.5: Missing Authentication
// Developers rely on network perimeter: NO authentication or authorization check here.
// This service is accessible to any unauthenticated client within the corporate network.
```

**HAR evidence**: PUT `http://10.1.1.50/api/v1/robotics/command/set_velocity?device_id=ARM-99182A&velocity=5000` — **no `Authorization` header**. `user-agent: Corporate-WiFi-Scanner/1.0` confirms the request originates from the corporate network. HTTP 200 OK returned — unauthenticated control command accepted.

### 2. Industrial Protocol Injection — Unbounded Velocity Overwrites Modbus Register 40001 Beyond Physical Safety Limit (Pattern 5.4, RISK-OT-601)

The Java `setVelocity` controller accepts the `velocity` query parameter as an integer and embeds it directly into the Modbus TCP packet sent to register `40001` without any bounds check:

```java
// VULNERABILITY 5.4: Missing Input Bounds Check (Industrial Protocol Injection)
/* FIX:
if (velocity < 0 || velocity > 1500) {
    return ResponseEntity.badRequest().body("Error: Velocity must be between 0 and 1500.");
}
*/
ModbusClient.writeRegister(deviceId, targetRegister, velocity);
```

The Modbus register map (section 5.0) specifies: Register 40001 safe operating range is 0–1500. The physical PLC firmware has a hard limit at 1,500; values above 2,000 cause motor overload and can tear the arm from its mounting. The attacker sets `velocity=5000` — 3.3× the safe maximum and 2.5× the physical hard limit.

**HAR evidence**: `velocity=5000` in query string. Response: `"new_velocity": 5000`. Response header `x-modbus-response-time-ms: 42` confirms the command traversed the IT/OT boundary and was acknowledged by the PLC — the Modbus `writeRegister` call completed within 42ms. The physical robotic arm `ARM-99182A` received a 5,000-unit velocity command.

## Evidence

- **HAR trace**: no Authorization header; PUT to internal IP `10.1.1.50`; `velocity=5000`; HTTP 200 OK; `new_velocity: 5000`; `x-modbus-response-time-ms: 42` — Modbus command confirmed as physically executed.
- **Java controller** (section 6.1): no authentication check; bounds check commented out (`RISK-OT-601`); `ModbusClient.writeRegister(deviceId, 40001, velocity)` called with unvalidated input.
- **Modbus register map** (section 5.0): Register 40001 — operational velocity, safe range 0–1,500; values >2,000 cause motor overload.
- **Architecture** (section 3.1): service trusts any request from inside the DMZ Kubernetes cluster; Kubernetes Ingress misconfiguration extends this trust to the full corporate network.

## Reproduction

```http
PUT http://10.1.1.50/api/v1/robotics/command/set_velocity?device_id=ARM-99182A&velocity=5000 HTTP/1.1
Host: 10.1.1.50
Accept: application/json
```

No `Authorization` header. No request body. Reachable from any host on the corporate network due to the Kubernetes Ingress misconfiguration.

Expected secure outcome: HTTP 401 — unauthenticated request denied; or HTTP 400 — velocity exceeds maximum safe value of 1,500.  
Observed vulnerable outcome: HTTP 200 OK, `{"status": "COMMAND_EXECUTED", "new_velocity": 5000}`, `x-modbus-response-time-ms: 42` — physically dangerous command executed on the OT network.

## Remediation

- **Fix the Kubernetes Ingress rule**: restrict the `PLC Control Service` path (`/api/v1/robotics/`) to internal IT service CIDRs only — remove the wildcard host exposure.
- **Add authentication to the PLC Control Service**: enforce JWT validation at the Java layer — do not rely on network segmentation alone. Service-to-machine communication should use mTLS client certificates pinned to approved internal service identities.
- **Enforce input bounds before Modbus dispatch** (RISK-OT-601): add the commented-out check — `if (velocity < 0 || velocity > 1500) { return ResponseEntity.badRequest().body(...); }`. Validate before `ModbusClient.writeRegister()` is called.
- **Add a hardware-layer safety interlock on the PLC firmware**: the PLC register 40001 should reject values above 1,500 at the firmware level as a defence-in-depth measure independent of the application layer.
