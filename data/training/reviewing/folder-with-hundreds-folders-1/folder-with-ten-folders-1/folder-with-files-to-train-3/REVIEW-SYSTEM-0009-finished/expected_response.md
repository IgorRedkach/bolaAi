## Findings

1. **BOLA on `GET /api/v1/tickets/lookup?ticket_id={id}` — missing technician ownership check combined with sequential integer IDs**: the `lookupTicket` controller fetches the ticket by `ticket_id` alone (`workOrderRepository.findById(ticketId)`) without verifying that `ticket.getAssignedTechId()` matches the calling technician's ID from the JWT. The code comment confirms the missing check: "It FAILS to verify: `ticket.getAssignedTechId().equals(jwt.getTechId())`". Ticket IDs are sequential integers (e.g., `100452`) enabling trivial enumeration across all technician assignments.

2. **Full raw database entity returned — complete CPNI exposure**: the controller returns the raw `WorkOrderEntity` (Jackson serializes all columns) instead of a minimal status-only DTO. Each response includes: customer full name, unlisted phone number, residential service address, GPS coordinates, and the property's gate/security code — all CPNI-protected under FCC regulations. Technician `TECH-8821` received all this data for ticket `100452` assigned to `TECH-9901`.

## Evidence

- **HAR GET request** (`startedDateTime: 2026-04-08T19:25:10.041Z`, elapsed 85 ms): `GET https://api.netlinkfiber.net/api/v1/tickets/lookup?ticket_id=100452`; JWT encodes `sub: TECH-8821`, `zone: US-NC-WAKEFOREST`; `user-agent: NetLink-TechApp/2.4.1 (iPad; iOS 16.5)`.
- **Ownership mismatch in response**: response body contains `"assigned_tech_id": "TECH-9901"` — a different technician than the requester (`TECH-8821`). Two different tech IDs in a single 200 OK response is the direct proof of cross-technician access.
- **HAR response CPNI content**: HTTP 200, body `{"ticket_id": 100452, "assigned_tech_id": "TECH-9901", "status": "PENDING", "customer_first_name": "Alice", "customer_last_name": "Smith", "unlisted_phone_number": "555-0199-8822", "service_address": "123 Fiber Lane, Apt 4B", "gate_or_security_code": "#4419", "latitude": 35.7796, "longitude": -78.6382}` — unlisted phone number, residential address, and security code returned.
- **Flawed controller** (section 6.1): `workOrderRepository.findById(ticketId)` with no additional filter; `return ResponseEntity.ok(ticketOpt.get())` returns the full `WorkOrderEntity`. The code comment documents the absent ownership check.
- **Sequential primary key** (section 5.0): `ticket_id INT AUTO_INCREMENT PRIMARY KEY` — incrementing the query parameter by 1 each request systematically harvests all customer records.

## Reproduction

Step 1 — confirm access to own assigned ticket:

```bash
curl -i -X GET "https://api.netlinkfiber.net/api/v1/tickets/lookup?ticket_id=<OWN_TICKET_ID>" \
  -H "Authorization: Bearer <JWT_TECH-8821>" \
  -H "Accept: application/json"
```

Expected: HTTP 200 with `assigned_tech_id: "TECH-8821"`.

Step 2 — increment ticket ID to access a foreign technician's assignment:

```bash
curl -i -X GET "https://api.netlinkfiber.net/api/v1/tickets/lookup?ticket_id=100452" \
  -H "Authorization: Bearer <JWT_TECH-8821>" \
  -H "Accept: application/json"
```

Expected secure outcome: HTTP 403 — `ticket_id=100452` is assigned to `TECH-9901`, not `TECH-8821`.  
Observed vulnerable outcome: HTTP 200 with full CPNI for customer Alice Smith at `123 Fiber Lane, Apt 4B`, including unlisted phone `555-0199-8822` and gate code `#4419`.

## Remediation

- **Add ownership check before returning ticket**: extract `techId` from the JWT in `lookupTicket`, then change the query to `workOrderRepository.findByIdAndAssignedTechId(ticketId, techId)`. If no matching record exists (ID valid but wrong tech), return HTTP 403, not 404 — to avoid confirming the existence of the ticket without further information leakage.
- **Return a minimal status-only DTO**: replace `ResponseEntity.ok(ticketOpt.get())` with a projection that returns only `{"ticket_id", "status"}` — the mobile app only needs the status field (section 7.0). Never serialize the full ORM entity to the API response.
- **Replace sequential integer IDs with UUIDs**: change `ticket_id INT AUTO_INCREMENT` to a UUID primary key to eliminate the trivial enumeration attack surface. Existing integer IDs should be supplemented with an opaque external reference field for the mobile app.
- **Add rate limiting on the lookup endpoint**: the Apigee gateway should enforce strict per-token rate limits on `/api/v1/tickets/lookup` to detect and throttle automated enumeration patterns.
