# HR & Payroll Management API — REST Reference (v1)

**Base URL:** `https://api.hrms.internal/v1`
**Auth:** Every endpoint requires `Authorization: Bearer <token>` issued by the SSO gateway.
**Format:** REST only. JSON. No GraphQL.

---

## Employee Profiles

### GET /employees/{employeeId}/profile

Returns the full profile of the specified employee: name, job title, department, hire date, and home address.

**Path parameters:**
- `employeeId` (string): Unique employee ID (e.g. `emp-1001`).

**No documentation states the server checks whether the token holder is the employee or an authorized HR manager for that employee.**

**Response 200:**
```json
{
  "employeeId": "emp-1001",
  "name": "Alice Smith",
  "title": "Software Engineer II",
  "department": "Engineering",
  "hireDate": "2021-03-15",
  "homeAddress": "99 Oak Ave, Springfield"
}
```

---

## Payroll Records

### GET /payroll/{payrollId}

Returns a single payroll record: gross salary, deductions, net pay, and the employee it belongs to.

**Path parameters:**
- `payrollId` (string): Unique payroll record ID (e.g. `pay-5501`).

**No documentation states the server verifies the token holder is the referenced employee or their manager.**

**Response 200:**
```json
{
  "payrollId": "pay-5501",
  "employeeId": "emp-1001",
  "grossSalary": 95000,
  "deductions": 12000,
  "netPay": 83000,
  "period": "2026-Q1"
}
```

---

## Salary Updates

### PATCH /employees/{employeeId}/salary

Updates the base salary for the specified employee.

**Path parameters:**
- `employeeId` (string): The employee whose salary to update.

**No documentation states the server checks the token holder is an HR admin authorized to update this specific employee's salary. Any authenticated user who knows the employeeId could attempt to call this.**

**Request body:**
```json
{ "baseSalary": 100000 }
```

**Response 200:**
```json
{ "employeeId": "emp-1001", "baseSalary": 100000, "updatedAt": "2026-03-23T10:00:00Z" }
```

---

## Department Roster

### GET /departments/{departmentId}/employees

Returns a list of all employees in the specified department.

**Path parameters:**
- `departmentId` (string): Unique department ID (e.g. `dept-eng`).

**No documentation states the server checks whether the token holder has access to view this department's roster.**

**Response 200:**
```json
[
  { "employeeId": "emp-1001", "name": "Alice Smith", "title": "Software Engineer II" },
  { "employeeId": "emp-1002", "name": "Bob Jones", "title": "Senior Engineer" }
]
```

---

## Performance Reviews

### POST /performance-reviews

Submits a performance review. The request body includes the `revieweeEmployeeId` (the employee being reviewed) and `reviewerEmployeeId` (the person submitting).

**No documentation states the server verifies the `reviewerEmployeeId` in the body matches the authenticated token. Any user can set `reviewerEmployeeId` to any value.**

**Request body:**
```json
{
  "revieweeEmployeeId": "emp-1001",
  "reviewerEmployeeId": "emp-2050",
  "period": "2026-Q1",
  "rating": 4,
  "comments": "Excellent contributions this quarter."
}
```

**Response 201:**
```json
{ "reviewId": "rev-7701", "status": "SUBMITTED" }
```

---

## Notes

- REST only; no GraphQL or SOQL.
- All IDs (`employeeId`, `payrollId`, `departmentId`, `reviewId`) are opaque strings in production.
- Salary and payroll data is considered highly sensitive (PII + financial).
- Rate limit: 30 requests per minute per token.
