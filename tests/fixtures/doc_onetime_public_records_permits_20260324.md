# Public records permits API (municipal)

Bearer token required. The documentation does not state object-level ownership checks.

REST only — no GraphQL, SOQL, or Salesforce.

## Endpoints

- `GET /permits/v2/applications/{applicationId}` — Fetch permit application details.
- `POST /permits/v2/batch/status-update` — Body: `{ "applicationIds": ["a-1", "a-2"], "status": "approved" }`.
- `GET /permits/v2/departments/{departmentId}/inspections/{inspectionId}` — Read inspection details.
- `PATCH /permits/v2/applications/{applicationId}/assignee` — Body: `{ "userId": "u-123" }`; no mention that caller can only reassign applications in their own department.
