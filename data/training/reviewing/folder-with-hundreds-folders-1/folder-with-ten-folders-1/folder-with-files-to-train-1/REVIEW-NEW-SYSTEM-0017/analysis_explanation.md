# Analysis Explanation

**System analysed:** ScholarNet Assessment Gateway v5.5.0 (EdTech / Online Assessment)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 4.0 (Attack Surface)** — two patterns: Pattern 9.1 (mass assignment) and Pattern 8.3 (trusting client-side logic). Noted RISK-ED-210 and the core flaw: `req.body` spread directly into Prisma ORM `update`.

2. **Read Section 5.0 (Database schema)** — confirmed the `exam_attempts` table stores student-controlled and administrative fields in the same row. Identified `final_score`, `exam_status`, `is_manually_overridden`, `grading_notes` as the administrative columns the attacker targets.

3. **Read Section 6.0 (Node.js code)** line by line:
   - Line 119–125: `prisma.examAttempt.update({ data: { ...req.body, submitted_at: new Date() } })` — the spread of `req.body` is the mass assignment flaw
   - Lines 128–131: `if (updatedAttempt.exam_status === 'SUBMITTED')` — the SQS trigger is conditional on the status, which the attacker can control

4. **Read Section 7.2 (malicious payload)** — identified the exact fields injected by the attacker: `exam_status: "GRADED"`, `final_score: 100.00`, `is_manually_overridden: true`, `grading_notes: "Perfect score validated by system admin."`

5. **Analysed the HAR trace**:
   - Request URL: `POST /api/v2/assessments/attempts/att-99182A/submit`
   - JWT decoded: `{"subject":"stud_88192A","role":"student"}` — student role only
   - Request body contains all four injected administrative fields
   - Response: `200 OK` + `"Exam successfully submitted and saved to repository."` — confirms ORM accepted all fields
   - Header `x-orm-latency-ms: 45` — confirms database write occurred

6. **Constructed reproduction steps** using only:
   - The exact endpoint URL from the HAR (`att-99182A`)
   - The exact JWT token from the HAR
   - The exact malicious payload fields from Section 7.2 and the HAR
   - The exact response message from the HAR

## Consistency Guard
- No data from any other training example was used.
- All URLs, attempt IDs, JWT values, field names, and response messages in expected_response.md are drawn directly from this folder's context.txt.
- The grading bypass dimension (SQS not triggered when `exam_status = GRADED`) is grounded in the code logic at Section 6.0 lines 128–131 and cited specifically.
