# Municipal Permit Management System — API v1 (internal)

Bearer token per user account. **No statement that a caller may only access their own permit applications.**

REST only — **no GraphQL.**

## Endpoints

- `GET /permits/v1/applications/{applicationId}` — Return full permit application (applicant name, address, construction details). No ownership or role check is described.
- `POST /permits/v1/inspections/{inspectionId}/approve` — Mark an inspection as approved. Requires **inspector role**. **Does not state** the inspector must be the one assigned to that specific inspection.
- `GET /permits/v1/applicants/{applicantId}/documents` — Return all uploaded documents (site plans, surveys) for an applicant. **No claim** that the caller must be the applicant or an assigned case worker.
