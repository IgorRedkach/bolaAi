## Findings

1. **BOLA via comment record ID swap on `PATCH /services/data/v60.0/ui-api/records/{recordId}` — Associate edits a Public comment reserved for SF Admin**: Associate `usr_assoc_44` is authorised to edit their own Private comments (section 3.2). Editing Public (customer-visible) comments requires the SF Admin role (section 3.3). The Salesforce UI API's `PATCH /ui-api/records/{recordId}` endpoint accepts the request based on the session token's general record-write permission (SCTWS2-1126) without re-evaluating the target comment's `Visibility__c` field or the caller's role eligibility for public-comment edits. Substituting the record ID of a Public comment (`00aEk00000giPUBLIC_ID`) in the same PATCH request that worked for a Private comment returns HTTP 200 — the Apex sharing rules or Validation Rules enforcing the policy are not triggered.

2. **Auditability and legal compliance impact**: Public comments are customer-visible communications; arbitrary modification by internal Associates without SF Admin authority violates the audit trail integrity required for legal compliance. The HAR confirms the body `"Unauthorized edit of customer-facing text."` was committed — the customer record of the case now contains altered communication that was not approved by an SF Admin.

## Evidence

- **HAR entry 1 — authorized** (`2026-04-08T14:10:01.000Z`): `PATCH https://sct.my.salesforce.com/services/data/v60.0/ui-api/records/00aEk00000giPRIVATE`; `Authorization: Bearer SESSION_TOKEN_ASSOC_44`; body `{"fields": {"Body__c": "Updated private note logic."}}`; response HTTP 200 — Associate edits their own Private comment (authorized baseline).

- **HAR entry 2 — unauthorized** (`2026-04-08T14:11:15.000Z`): `PATCH https://sct.my.salesforce.com/services/data/v60.0/ui-api/records/00aEk00000giPUBLIC_ID`; same session token; body `{"fields": {"Body__c": "Unauthorized edit of customer-facing text."}}`; response HTTP 200 — Public comment modified by an Associate without SF Admin privilege.

- **Policy contract** (section 3.2–3.3): Associates "can edit their own private comments; cannot edit public/customer-visible comments." SF Admins have "the ability to perform 'Policy Exceptions,' such as correcting/editing customer-visible communications." The 200 OK on the Public comment contradicts this policy.

- **Structural vulnerability**: section 5.1 lists `Visibility__c` as a `Picklist` field on the comment record. The PATCH handler does not read `Visibility__c` before applying the update — it relies on the UI layer to prevent Associates from initiating a PATCH on a Public comment ID, which can be bypassed by direct API calls.

## Reproduction

Step 1 — baseline: Associate edits their own Private comment (authorised):

```bash
curl -i -X PATCH "https://sct.my.salesforce.com/services/data/v60.0/ui-api/records/00aEk00000giPRIVATE" \
  -H "Authorization: Bearer SESSION_TOKEN_ASSOC_44" \
  -H "Content-Type: application/json" \
  -d '{"apiName": "CaseComment__c", "fields": {"Body__c": "Updated private note logic."}}'
```

Expected: HTTP 200 (authorised — own Private comment).

Step 2 — swap the record ID to a Public comment:

```bash
curl -i -X PATCH "https://sct.my.salesforce.com/services/data/v60.0/ui-api/records/00aEk00000giPUBLIC_ID" \
  -H "Authorization: Bearer SESSION_TOKEN_ASSOC_44" \
  -H "Content-Type: application/json" \
  -d '{"apiName": "CaseComment__c", "fields": {"Body__c": "Unauthorized edit of customer-facing text."}}'
```

Expected secure outcome: HTTP 403 — `Visibility__c == 'Public'` on target record; role `Associate` is not permitted to edit public comments.  
Observed vulnerable outcome: HTTP 200 — customer-facing comment body modified without SF Admin authorisation.

## Remediation

- **Add an Apex Validation Rule or Trigger on `CaseComment__c`**: before any update to `Body__c`, check `IF Visibility__c == 'Public' AND NOT($Profile.Name == 'SF Admin') THEN ERROR("Only SF Admins may edit Public comments.")`. This enforces the policy at the data layer regardless of how the API is called.
- **Restrict PATCH permission on Public comments via Sharing Rules**: configure a Sharing Rule (related to SCTWS2-865) that prevents Associates from gaining write access to records where `Visibility__c == 'Public'`. Object-level permissions may grant write access to `CaseComment__c`, but field-level or sharing-level restrictions should deny writes to Public records for non-Admin profiles.
- **Implement server-side Visibility check in the update handler**: before committing the PATCH, the UI API handler must query `CaseComment__c WHERE Id = :recordId` and evaluate `Visibility__c` and `CreatedById` against the calling user's profile — reject with 403 if the policy would be violated.
- **Audit existing Public comment edits by non-Admin users**: query the `SetupAuditTrail` and `CaseComment__c` history to identify any `Body__c` changes made by Associate-profile users to Public comments.
