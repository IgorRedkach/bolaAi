# Analysis Explanation — BOLA-0096-P73-HR

## What was wrong

### 1. Wrong endpoint, API version, and resource type throughout

Original `expected_response.md` used `/api/v1/resources/RES-*` throughout. Section 2.0 and HAR both specify `/api/v3/items` with `ITE-*` IDs. Fixed all reproduction steps to use the correct path and ID format.

### 2. HAR primary (DELETE) was not used — GET was shown instead

The HAR captures a `DELETE /api/v3/items/ITE-2096` request — the most critical demonstration for Pattern 7.3 (Insufficient Logging of Critical Actions), since DELETE is the canonical "critical action." The original response showed only GET requests, ignoring the HAR entirely. Rewrote to make DELETE the primary Step 2, matching the HAR exactly.

### 3. Pattern 7.3 (insufficient critical-action logging) not explained

Original Step 3 stated "No specific variant documented for Pattern 7.3 — use Steps 1-2." This fails to distinguish Pattern 7.3 from ordinary BOLA.

Pattern 7.3 is specifically about the absence of mandatory audit logging for destructive operations. In payroll systems, DELETE and PATCH of salary/payroll records are SOX-regulated critical actions requiring immutable audit trails. The handler executes these operations cross-tenant with no log entry, making:
- forensic investigation impossible after a breach,
- compliance audits unable to detect the unauthorized actions,
- regulatory violations (SOX, GLBA, labor law) certain.

Added explicit explanation of this mechanism and the compliance context.

### 4. PATCH added as Pattern 7.3 extension

PATCH of payroll data (salary manipulation) is a critical action equally requiring mandatory logging. Added PATCH step to show the full attack surface.

## Domain context

WageFlow is an HR / Payroll Processing platform. Items represent payroll records, salary configurations, or benefit data. Cross-tenant DELETE destroys another employer's payroll records. Cross-tenant PATCH commits undetectable payroll fraud. Both violate SOX (Section 302/404), GLBA, and labor regulations. Without audit logs, the victim cannot detect, investigate, or remediate the attack.

## HAR alignment

HAR primary: `DELETE /api/v3/items/ITE-2096` with `ORG-19DD` JWT → HTTP 200 → `tenantId: "ORG-9225"` with `sensitiveData`. This is Step 2. Endpoint version and resource type corrected throughout.
