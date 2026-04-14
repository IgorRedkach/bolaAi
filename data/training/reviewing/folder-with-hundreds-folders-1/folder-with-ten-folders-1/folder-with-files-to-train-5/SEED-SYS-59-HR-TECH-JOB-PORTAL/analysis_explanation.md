## Analysis reasoning

I reviewed the JobCore Candidate Portal API v3.3.0 architecture specification, Python Django resolver code, Django model, and HAR trace.

1. **Mass assignment root cause**: the `setattr(app, key, value)` loop applies every key in the `input` dictionary as an attribute on the `Application` model instance. The Django model has `status` as a field with an enum constraint (choices), which means `setattr(app, 'status', 'OFFER_MADE')` will succeed — the ORM validates the enum value against `status_choices` but does not enforce which roles can write it. RISK-HR-GQL-112 documents this explicitly: "accept all valid input fields to simplify form submission logic" — the philosophy of convenience over security.

2. **BOLA check is correct but insufficient**: `require_candidate_ownership(user_id, app)` correctly verifies ownership (section 6.1). The candidate owns `app_22190`. But ownership is not the same as authorization to write all fields on the owned object. A candidate owning an application does not authorize them to set `status` — that requires the `RECRUITER` role. The resolver confuses object-level authorization (who can access the object) with field-level authorization (which fields the caller can write on the object they access).

3. **HAR `status: OFFER_MADE` in response confirms full write**: the response body contains `"status": "OFFER_MADE"` — this is the `findById` + updated result returned by the Django resolver after `app.save()`. The HAR response time is 68ms — consistent with a fast ORM update. No error in the response.

4. **Business logic impact**: the `OFFER_MADE` status would trigger downstream HR notification workflows — "a notification to HR" (section 4.1). A previously `REJECTED` candidate can force their application into `OFFER_MADE` state, triggering an official offer process. This is not just data corruption — it creates legal/contractual obligations for the employer.

5. **Same pattern, different domain from SEED-SYS-55**: this is a similar mass assignment vulnerability to SEED-SYS-55 (ConsumerProfile GraphQL API) but in an HR context. The key difference is the target field: SEED-SYS-55 targets `role` (authentication escalation), while this targets `status` (business process manipulation). The root cause is identical: `setattr`/spread over untrusted input without an allowlist.
