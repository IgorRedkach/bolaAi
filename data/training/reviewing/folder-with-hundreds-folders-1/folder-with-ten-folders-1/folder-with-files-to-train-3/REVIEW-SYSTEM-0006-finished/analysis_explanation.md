## Analysis reasoning

I reviewed the PeopleSync HCM specification (v6.1.4) and the accompanying HAR trace as engineering artifacts, not as pre-labeled vulnerability text.

1. **API version routing as security boundary gap**: section 2.1 confirms both v3 (Go microservices) and v1 (Java Tomcat monolith) are reachable through the same Kong gateway with the same JWT. Section 3.2 states that v3 enforces `payroll:write` scope for salary modifications. The v1 endpoint's Kong rule is "Requires valid JWT (Basic Identity check only)" — no scope enforcement for restricted field operations.

2. **BeanUtils mass assignment root cause**: section 6.2 shows `BeanUtils.populate(employeeRecord, payload)` with the comment "BeanUtils blindly copies EVERY key from the payload map into the Employee object." This is the direct mechanism enabling the injection. The restricted Oracle columns (`SALARY_BAND`, `HOURLY_WAGE`, `MANAGER_APPROVAL_BYPASS`) have corresponding setter methods on the JPA entity that BeanUtils can invoke via reflection.

3. **Dual-endpoint proof via HAR**: the two HAR entries together form the complete proof. Entry 1 (`/api/v1/employee/update`, HTTP 200, `X-Powered-By: Apache Tomcat`) confirms the legacy endpoint accepted the restricted fields. Entry 2 (`GET /api/v3/employees/EMP-1099/profile`, `x-microservice: go-profile-svc`) confirms the Oracle database now reflects `salary_band: "EXEC_TIER_1"` and `manager_approval_bypass: 1` — the shared Oracle persistence layer propagated the injected values.

4. **Scope mismatch proof**: the JWT in both requests encodes `scopes: ["profile:read", "profile:write_basic"]`. The restricted fields (`SALARY_BAND`, `MANAGER_APPROVAL_BYPASS`) require `payroll:write` scope per section 3.2 — which is absent from this token. The v1 endpoint never checks for this scope.

5. **`manager_approval_bypass: 1` significance**: `MANAGER_APPROVAL_BYPASS NUMBER(1) DEFAULT 0` in the Oracle schema (section 5.0) is a boolean flag that, when set to 1, removes the requirement for managerial sign-off on payroll changes — a compounding privilege escalation beyond just the salary band change.

6. **Reproduction path**: v3 POST first to confirm the secure baseline, then v1 POST with the same JWT containing restricted fields, then v3 GET for verification. Uses only the actual endpoint URLs, employee ID, and field names from the context.
