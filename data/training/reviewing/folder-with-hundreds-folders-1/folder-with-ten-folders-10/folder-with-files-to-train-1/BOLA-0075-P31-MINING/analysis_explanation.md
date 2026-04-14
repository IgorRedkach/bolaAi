## Analysis reasoning

1. **Wrong endpoint and ID format**: the original used `/api/v1/resources/RES-*` — context specifies `/api/v1/objects/OBJ-*` and HAR uses `OBJ-2075`. All corrected.

2. **Pattern 3.1 (Client-Assumed Authority) root cause distinction**: Pattern 3.1 is an insecure design flaw, not just a missing WHERE clause. The design was built with the assumption that authenticated clients would only access their own objects — there is no server-side authority validation because the designer assumed the client's authentication was sufficient proof of authority. This is different from Pattern 1.1 (where the check simply wasn't added) — Pattern 3.1 means the design principle itself is flawed. The remediation must address the design, not just the query.

3. **Write path is essential for Pattern 3.1 "authority"**: the word "authority" in Pattern 3.1 implies more than read access. A client assuming authority would also attempt writes and deletes — in a mining fleet context, this means issuing operational commands to another company's equipment.

4. **Mining/IoT context**: `status: "suspended"` via PATCH on a fleet object could suspend a mining vehicle's IoT telemetry, take equipment offline, or inject false status readings — disrupting extraction operations.

5. **RISK-31-075 is a documented, known gap**: handler written before tenant isolation policy, remediation blocked pending DB migration #DB-175.
