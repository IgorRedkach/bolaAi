# UniPortal API — Student Services

## Overview
UniPortal provides student profile, finance, and discipline records.

## Authentication
- JWT required. Claims: `campusId`, `role` (`student`, `advisor`, `registrar`, `admin`).

## Endpoints
- **GET /uni/api/students/{studentId}** — Student profile.
- **GET /uni/api/students/{studentId}/finance/{invoiceId}** — Tuition invoice details.
- **PATCH /uni/api/students/{studentId}/discipline/{caseId}** — Update disciplinary case fields.
- **GET /uni/api/admin/audit/{userId}** — Admin audit history.

## Policy Notes
- "Advisors should access assigned students only" (not enforced details).
- "Admins can access audit records" (no campus scope details).
