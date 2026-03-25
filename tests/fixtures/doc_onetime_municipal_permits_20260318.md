# Municipal Permits & Inspections — Internal API (v1)

Authentication: OAuth 2.0 bearer token required for all endpoints. Each user belongs to one department.

**No per-application or per-document ownership verification is described below.**

REST only — no GraphQL, no SOQL.

## Endpoints

- `GET /permits/v1/applications/{applicationId}` — Returns full application details: applicant name, SSN (last 4), property address, permit type, status, and internal reviewer notes. Requires valid token.

- `POST /permits/v1/inspections/{inspectionId}/schedule` — Body `{ "date": "2026-04-15", "inspectorId": "insp-42" }`. Schedules or reschedules a field inspection for the given inspection record. Does **not** state that the caller must be the assigned inspector or the original applicant.

- `GET /permits/v1/applications/{applicationId}/documents/{documentId}` — Downloads an attached document (blueprints, site photos, personal identification scans). Returns binary. No statement that the requesting user must be the applicant or an authorized reviewer for that application.

- `POST /permits/v1/batch/status-update` — Body `{ "applicationIds": ["app-101", "app-102"], "newStatus": "approved" }`. Updates status for multiple applications at once. Does **not** verify the caller is the assigned reviewer for every application in the batch.

## Roles

- **Applicant** — submits applications, uploads documents.
- **Inspector** — performs site visits, marks inspection complete.
- **Reviewer** — approves or denies applications.
- **Admin** — full access.

Role enforcement at endpoint level is not described beyond "valid token required."
