# Analysis Explanation

**System analysed:** AeroSync Global PSS v14.1.0 (Aviation / Loyalty Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 2.2 (Service Mesh)** — noted the SkyRewards Loyalty Service "relies on a private internal network and trusts any requests coming from within the Kubernetes cluster." This is the design assumption that creates the blast radius for the XXE attack.

2. **Read Section 4.0 (Attack Surface)** — two patterns: Pattern 7.1 (XXE) and Pattern 1.3 (missing function-level auth). Noted RISK-AVIA-812 and the attack chain: malicious XML entity → confused deputy GET → unauthenticated `add-miles` execution.

3. **Read Section 6.0 Java controller** line by line:
   - Three `setFeature` calls explicitly commented out — confirms DOCTYPE processing is enabled
   - `builder.parse(new InputSource(...))` — entity resolved here, making the internal HTTP call
   - No `FlightNumber` format validation before downstream use

4. **Read Section 6.0 Go Loyalty service**:
   - `http://loyalty-svc.internal:8080/internal/v1/accounts/:account_number/add-miles`
   - `db.Exec(UPDATE ... SET total_miles_balance = total_miles_balance + $1 ...)` — unconditional SQL update
   - Code comment: "Trusting the network boundary instead of explicitly authenticating the caller"

5. **Analysed the HAR trace**:
   - Request: `POST /b2b/soap/v1/AvailabilityQuery` with full malicious DOCTYPE payload
   - API key `ak_agency_77182X_live` — legitimate B2B key
   - Response: `500 Internal Server Error`
   - **Key finding:** Response body error message contains `{"status": "MILES_CREDITED"}` — the Loyalty service responded before the casting error. This proves the XXE was successful and miles were credited despite the 500 response code.

6. **Identified the critical "blind" success pattern**: A 500 error in an XXE scenario does not mean the attack failed. The internal service state was already mutated before the error propagated.

7. **Constructed reproduction steps** using only:
   - The exact endpoint and API key from the HAR
   - The exact malicious XML payload from Section 7.0
   - The exact loyalty account `10045299` and amount `500000` from the malicious payload
   - The exact error string `{"status": "MILES_CREDITED"}` from the HAR response body

## Consistency Guard
- No data from any other training example was used.
- All endpoints, API keys, account numbers, XML payloads, and error messages in expected_response.md are drawn directly from this folder's context.txt.
- The "5xx = success" observation is explicitly grounded in the HAR response body content, not inferred from outside this context.
