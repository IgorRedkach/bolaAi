# PeopleOps HR API — Technical Reference

## Overview

PeopleOps is an internal HR system for employee records, payroll, and performance reviews. API is consumed by the HR portal, manager dashboards, and payroll integrations.

## Authentication

- OAuth2 Bearer token. Claims: `sub` (employeeId), `role` (employee|manager|hr_admin), `departmentId`.
- Token is required for all endpoints.

## Endpoints

### Employee Records

- **GET /hr/api/employees/{employeeId}** — Returns employee profile: name, salary, SSN (last 4), department, managerId. Requires valid token.
- **PATCH /hr/api/employees/{employeeId}** — Update employee fields (e.g. department, title). Requires valid token with role manager or hr_admin.
- Documentation does not state that a manager can only access employees in their own department.

### Payroll

- **GET /hr/api/payroll/{employeeId}/stubs** — Returns payroll stubs (salary, deductions, net pay). Requires valid token.
- No mention that the caller must be the employee themselves or their direct manager.

### Performance Reviews

- **GET /hr/api/reviews/{reviewId}** — Returns performance review details: rating, comments, reviewerId, employeeId. Requires valid token.
- **POST /hr/api/reviews** — Create a new review. Body: `{ "employeeId": "...", "rating": 4, "comments": "..." }`.
- No documentation states that only the assigned reviewer or HR admin can create or view a review.

## Data Model

- **Employee** — employeeId, name, salary, ssn_last4, departmentId, managerId.
- **PayrollStub** — stubId, employeeId, period, gross, deductions, net.
- **Review** — reviewId, employeeId, reviewerId, rating, comments, period.

## Security Note

Authorization is described only as "valid token and appropriate role". No per-object or per-department ownership checks are documented for any endpoint.
