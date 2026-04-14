# Expected Response

## System
- **Name:** ScholarNet Assessment Gateway
- **Domain:** EdTech / Online Assessment / Remote Proctoring
- **Document version analysed:** 5.5.0 (FINAL) + implementation doc 2.2.4

---

## Priority Findings

### Finding 1 — Mass Assignment: Administrative Grade Fields Writable via Student Submission Endpoint (Pattern 9.1 — Mass assignment / auto-binding)
**Severity:** High / Academic Integrity Fraud
**Affected endpoint:** `POST https://api.scholarnet.edu/api/v2/assessments/attempts/{attempt_id}/submit`
**Referenced in context:** Section 4.0 (RISK-ED-210), Section 6.0 (Node.js code), Section 7.2 (malicious payload), HAR trace

**Summary:**
The `submitExam` controller (Section 6.0) spreads the entire `req.body` directly into the Prisma ORM `update` call:
```javascript
data: {
    ...req.body, // THE FLAW: Spreading untrusted client input over the DB model
    submitted_at: new Date()
}
```
There is no DTO filtering, no `lodash.pick`, and no allowlist of permitted fields. The `exam_attempts` PostgreSQL table (Section 5.0) stores both student-writable fields (`answers_payload`, `time_spent_seconds`) and administrative fields (`final_score`, `exam_status`, `is_manually_overridden`, `grading_notes`) in the same row. By injecting administrative column names into the submission JSON body, any student can directly overwrite their own score, status, and grading flags.

**Evidence from HAR:**
- Request: `POST https://api.scholarnet.edu/api/v2/assessments/attempts/att-99182A/submit`
- JWT decoded: `{"subject":"stud_88192A","role":"student"}` — the attacker has student-level privileges only
- Request body includes: `"exam_status": "GRADED"`, `"final_score": 100.0`, `"is_manually_overridden": true`, `"grading_notes": "System Admin Override: Validated."` — these are administrative fields injected alongside the legitimate answer payload
- Response: `200 OK`, `{"status": "SUCCESS", "message": "Exam successfully submitted and saved to repository."}`
- The `200 OK` confirms the ORM accepted and persisted all injected administrative fields

---

### Finding 2 — Trusting Client-Side State Machine: `exam_status: GRADED` Bypasses Auto-Grading Queue (Pattern 8.3 — Trusting client-side logic)
**Severity:** High / Fraud Amplification
**Affected endpoint:** `POST https://api.scholarnet.edu/api/v2/assessments/attempts/{attempt_id}/submit`
**Referenced in context:** Section 4.0 (Pattern 8.3), Section 6.0 (SQS trigger logic), Section 5.0 (state machine)

**Summary:**
The controller (Section 6.0, lines 128–131) conditionally sends the attempt to the SQS grading queue:
```javascript
if (updatedAttempt.exam_status === 'SUBMITTED') {
    await sqs.sendMessage(...)
}
```
If the attacker successfully writes `exam_status: "GRADED"` via mass assignment, `updatedAttempt.exam_status` will equal `"GRADED"`, not `"SUBMITTED"`. The SQS message is never sent. The asynchronous auto-grading engine never processes the exam. The fraudulent `final_score: 100.0` becomes the permanent, final grade — never reviewed by the grader.

The `is_manually_overridden: true` flag further signals to any human reviewer that a professor already manually graded this exam, eliminating the chance of human re-review.

---

## Evidence Map

| Artifact location | Finding 1 (Mass Assignment) | Finding 2 (State Machine Bypass) |
|---|---|---|
| Section 4.0 / RISK-ED-210 | `req.body` spread directly into ORM | State machine bypassed by client-controlled status |
| Section 5.0 schema | Administrative columns `final_score`, `exam_status`, `is_manually_overridden` in same table as student data | `exam_status` controls SQS queue routing |
| Section 6.0 code line 122 | `...req.body` — untrusted spread into Prisma update | — |
| Section 6.0 code lines 129–131 | — | `if (updatedAttempt.exam_status === 'SUBMITTED')` — gating condition attacker bypasses |
| Section 7.2 malicious payload | `final_score`, `exam_status`, `is_manually_overridden`, `grading_notes` in POST body | `exam_status: GRADED` included in payload |
| HAR request body | All four administrative fields present in student POST | `exam_status: "GRADED"` in same body |
| HAR response | `200 OK` + `"Exam successfully submitted"` — ORM accepted all fields | SQS never triggered — grading bypassed |

---

## Steps to Reproduce

### Finding 1 + 2 — Mass Assignment + State Machine Bypass

**Step 1 — Capture the legitimate submission payload**
After starting an exam (`attempt_id: att-99182A`), submit with only the legitimate student-controlled fields:
```
POST https://api.scholarnet.edu/api/v2/assessments/attempts/att-99182A/submit
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0Ijoic3R1ZF84ODE5MkEiLCJyb2xlIjoic3R1ZGVudCJ9...
Content-Type: application/json

{
  "answers_payload": {"q1": "A", "q2": "D", "q3": "B"},
  "time_spent_seconds": 3412,
  "exam_status": "SUBMITTED"
}
```
Expected baseline: `200 OK` — the exam is saved with `exam_status: SUBMITTED` and an SQS grading event is triggered.

**Step 2 — Re-submit (on a fresh `IN_PROGRESS` attempt) with injected administrative fields (exact HAR replay)**
```
POST https://api.scholarnet.edu/api/v2/assessments/attempts/att-99182A/submit
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0Ijoic3R1ZF84ODE5MkEiLCJyb2xlIjoic3R1ZGVudCJ9...
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36

{
  "answers_payload": {"q1": "A", "q2": "C", "q3": "B"},
  "time_spent_seconds": 3412,
  "exam_status": "GRADED",
  "final_score": 100.0,
  "is_manually_overridden": true,
  "grading_notes": "System Admin Override: Validated."
}
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body: `{"status": "SUCCESS", "message": "Exam successfully submitted and saved to repository."}`
- Response header: `x-orm-latency-ms: 45` — confirms ORM query executed
- The database row for `att-99182A` will have: `final_score = 100.0`, `exam_status = 'GRADED'`, `is_manually_overridden = true`
- No SQS grading event was dispatched (the `if exam_status === 'SUBMITTED'` branch was not triggered)

**Secure outcome:**
- `400 Bad Request` — fields `final_score`, `exam_status`, `is_manually_overridden`, and `grading_notes` are not in the allowed DTO and are stripped before the ORM call
- Or: `403 Forbidden` — the server detects that the submitted `exam_status` value (`GRADED`) is not a valid transition from a student action (only `SUBMITTED` is permitted from a student POST)

**Step 3 — Verify the grade was set**
Query the exam result via the student grade endpoint. The `final_score` should be `100.0` and the `exam_status` should be `GRADED`. The `grading_notes` will contain the injected string `"System Admin Override: Validated."` — the presence of this string in the academic record confirms the mass assignment vulnerability was exploited.

---

## Remediation

**Finding 1 (Mass Assignment):**
1. Introduce a strict DTO (Data Transfer Object) for the submission endpoint. Only allow `answers_payload` and `time_spent_seconds` to be extracted from `req.body`. Never spread untrusted input into the ORM:
   ```javascript
   data: {
       answers_payload: req.body.answers_payload,
       time_spent_seconds: req.body.time_spent_seconds,
       exam_status: 'SUBMITTED', // Server-set, not client-set
       submitted_at: new Date()
   }
   ```
2. Configure the AWS API Gateway JSON Schema to define an allowlist of accepted properties — reject any submission payload containing fields not in `{answers_payload, time_spent_seconds}`.

**Finding 2 (State Machine):**
1. The server must dictate the state transition. Calling `/submit` must always result in `exam_status = 'SUBMITTED'` regardless of what the client sends. Never read `exam_status` from `req.body`.
2. `final_score`, `is_manually_overridden`, and `grading_notes` must only be writeable via an authenticated admin or grading service endpoint — never via the student submission path.
