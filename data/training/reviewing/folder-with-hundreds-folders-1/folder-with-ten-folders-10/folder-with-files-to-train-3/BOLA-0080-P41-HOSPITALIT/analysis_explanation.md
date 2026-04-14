# Analysis Explanation — BOLA-0080-P41-HOSPITALIT

## What was wrong

### 1. Wrong API version throughout

Original response used `/api/v1/resources`. Section 2.0 and HAR both specify `/api/v2/resources`. Resource ID format `RES-*` is correct. Fixed API version.

### 2. HAR primary (DELETE) replaced with GET

HAR captures `DELETE /api/v2/resources/RES-2080`. Original response only showed GET. Made DELETE the primary Step 2.

### 3. Pattern 4.1 (confused deputy / brokerage failures) not demonstrated

Original Step 3 stated "No specific variant documented for Pattern 4.1 — use Steps 1-2." Pattern 4.1 requires explaining the confused deputy concept:
- The API server (deputy) holds elevated database privileges
- The client manipulates the deputy into acting on its behalf for resources it doesn't own
- The server is "confused" because it cannot distinguish between authorized and unauthorized target resources
- This is a brokerage failure: the broker (server) fails to enforce that the brokered operation is authorized

Added explicit explanation of the confused deputy mechanism and its relationship to the server's elevated database privileges.

### 4. PATCH added as extension attack

PATCH of another hotel's room rates or reservation data is an integrity attack through the confused deputy. Added Step 3.

### 5. Domain impact not articulated

Hotel PMS context: DELETE of reservation data destroys guest bookings; PATCH corrupts room rates. Both constitute active sabotage of competitor hotel operations.

## HAR alignment

HAR primary: `DELETE /api/v2/resources/RES-2080` with `ORG-F33C` JWT → HTTP 200 → `tenantId: "ORG-7DC8"` with `sensitiveData`. This is Step 2. API version corrected.
