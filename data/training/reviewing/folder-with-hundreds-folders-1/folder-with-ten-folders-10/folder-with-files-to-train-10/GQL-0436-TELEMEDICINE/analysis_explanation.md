# Analysis Explanation — GQL-0436-TELEMEDICINE

## What was wrong

### 1. HAR primary (`updateResource` mutation) completely missing from response

The HAR captures `updateResource(id: "R-2436", input: {status: "approved", ownerId: "attacker-0de01ef7"})` from `tenant-0de0` — a write mutation that modifies PHI and attempts ownership reassignment. The original response only showed `getResource` reads (Steps 1-2) and never reproduced the HAR mutation. Rewrote to make `updateResource` Step 1 (HAR primary).

### 2. Pattern 7.1 (PII/PHI leakage + logging failure) not explained

Original response declared Pattern 7.1 in the title but only demonstrated a cross-tenant read. Pattern 7.1's critical characteristic is the *dual* failure: BOLA enables cross-tenant access AND the access (especially mutations) generates no audit log entry. In telemedicine, HIPAA §164.312 mandates audit controls. The `auditLog` field in `ResourceData` schema confirms the platform designed for logging, but the resolver bypass means logs are never written. This dual failure — unauthorized PHI modification + no audit entry — was not explained in the original. Added explicit HIPAA context and `auditLog` schema reference.

### 3. `ownerId` override in input not highlighted

HAR input includes `ownerId: "attacker-0de01ef7"` — the attacker attempts to reassign ownership of the victim's consultation record to themselves. This is a mass assignment / ownership hijack vector that amplifies the Pattern 7.1 severity. Was not in original response. Added note that server must ignore client-supplied `ownerId`.

### 4. Speculative introspection removed; Redis cache added

Original Step 4 was speculative introspection with "if Pattern 6.1 also present" — introspection is not documented in GQL-0436 context. Removed. Section 2.0 documents Redis cache keyed by `resourceId` without user dimension — this is a concrete documented vulnerability for PHI leakage. Added as Step 4.

## Domain context

TeleCare is a Telemedicine / Remote Care platform. Resources represent patient consultation records containing PHI (diagnoses, treatment plans, prescriptions). Cross-tenant `updateResource` allows a competitor's tenant to modify or reassign patient records with no HIPAA audit trail. HIPAA breach notification (§164.410) is triggered, but since no log exists, the breach may never be detected or reported.

## HAR alignment

HAR primary: `updateResource(id: "R-2436", input: {status: "approved", ownerId: "attacker-0de01ef7"})` with `x-tenant-id: tenant-0de0` → HTTP 200 → `tenantId: "tenant-1ef7"`, `sensitiveField`, `internalNotes`. HAR request/response mismatch (response shows `getResource` shape) is a synthetic test harness artifact — noted in response.
