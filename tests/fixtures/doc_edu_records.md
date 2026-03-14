# CampusRecords API — Education Records Service

## Overview
CampusRecords stores student profiles, transcripts, and advisor notes.

## Authentication
- JWT bearer required.
- Claims: `userId`, `campusId`, `role` (`student`, `advisor`, `registrar`).

## Endpoints
- **GET /records/api/students/{studentId}** — Return profile and enrollment status.
- **GET /records/api/students/{studentId}/transcripts/{transcriptId}** — Return transcript PDF metadata and download link.
- **POST /records/api/students/{studentId}/advisor-notes** — Add advisor note.
- **GET /records/api/admin/audit/{userId}** — Admin audit history for user.

## Security notes
- Docs say roles are required but do not define per-student ownership checks.
- No statement that advisor must be assigned to that student.
