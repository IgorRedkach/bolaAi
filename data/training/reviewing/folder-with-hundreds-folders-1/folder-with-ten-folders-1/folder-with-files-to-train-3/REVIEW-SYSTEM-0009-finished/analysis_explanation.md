## Analysis reasoning

I reviewed the NetLink Fiber CPE Provisioning Gateway specification (v1.5.0) and the accompanying HAR trace as engineering artifacts, not as pre-labeled vulnerability text.

1. **Authorization model and dispatch ownership**: section 3.2 states a technician "should only see the names and addresses of customers on their specific daily dispatch route." Ownership is enforced by `assigned_tech_id` in `work_orders`. The controller (section 6.1) comments: "It FAILS to verify: `ticket.getAssignedTechId().equals(jwt.getTechId())`" — no ownership check executed.

2. **Sequential ID enumeration surface**: section 5.0 shows `ticket_id INT AUTO_INCREMENT PRIMARY KEY`. The HAR ticket ID is `100452` — a sequential integer. An attacker can iterate `100451`, `100452`, `100453`, ... to enumerate all active work orders for all technicians, harvesting customer data at scale.

3. **Full entity serialization**: section 6.1 notes "CRITICAL implementation detail: Returning the raw database entity 'WorkOrderEntity'. This allows Jackson to serialize and expose every single field." The response body in the HAR contains all CPNI-protected columns: `unlisted_phone_number`, `service_address`, `gate_or_security_code`, `latitude`, `longitude` — none of which the mobile app requires for a status lookup.

4. **HAR ownership mismatch**: the JWT encodes `sub: TECH-8821`. The response body contains `"assigned_tech_id": "TECH-9901"`. Two different technician identifiers in a single 200 OK response is the definitive BOLA proof signal.

5. **CPNI regulatory context**: the schema annotation (section 5.0) and classification (`CONFIDENTIAL / CPNI`) establish that `customer_first_name`, `customer_last_name`, `unlisted_phone_number`, `service_address`, and `gate_or_security_code` are all CPNI-protected customer data. Unauthorized disclosure violates FCC CPNI rules.

6. **Reproduction path**: baseline request against own ticket (to confirm normal access), then incremented ID request against foreign tech's ticket. Uses only the actual API URL, ticket ID, and JWT claims from the context.
