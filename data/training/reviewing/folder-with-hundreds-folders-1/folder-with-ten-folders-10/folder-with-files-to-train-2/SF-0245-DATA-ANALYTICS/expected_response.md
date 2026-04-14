## System

- System: InsightGraph Analytics API (Salesforce-Integrated) v3.0.0
- Domain: DATA ANALYTICS / BI PLATFORM
- Example ID: SF-0245
- Risk IDs: RISK-SF-245, RISK-SF-246

## Findings

### 1. Pattern 10.2 — Parameter Escalation: `c.CustomObjectController.getRecord` (HAR Primary)

**HAR evidence**: Aura action `c.CustomObjectController.getRecord` with `recordId: "001D145"`, client-supplied `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-99-4930"`.

**Pattern 10.2 (Parameter Escalation — Own Session Scope Extension)**: the attacker extends their own session's authorized scope by substituting the `recordId` parameter with IDs beyond their session's authorized records. The session is valid (authentication succeeds), but the `recordId` value escalates the session's access scope to include other users' `CustomRecord` objects. The controller does not validate that `recordId` belongs to the current user's authorized scope.

Root causes: Section 4.0 — controller runs `without sharing` (RISK-SF-245), bypassing OWD=Private on `CustomRecord`. SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` (RISK-SF-246). Section 8.0: client-supplied `recordId` directly interpolated into SOQL.

**Data Analytics / BI impact**: `CustomRecord` represents analytics dashboards, BI reports, or data pipeline configurations with proprietary analytical models. Cross-user parameter escalation exposes another analyst's proprietary BI models, report configurations, and internal analysis notes. SSN exposure (`SensitiveData__c: "SSN: 000-99-4930"`) from analytics records containing PII violates CCPA/GDPR.

Note: Section 4.0 names the method `getCustomRecordDetails` but HAR uses `getRecord` under `CustomObjectController`. HAR is authoritative — `c.CustomObjectController.getRecord` is the correct production action.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or DevTools. Identify `c.CustomObjectController.getRecord` in the `message` body. Record your own `recordId`.

**Step 2 — Parameter escalation: substitute victim `recordId` (primary HAR attack):**

```
POST https://94e8d145.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D94E8D145!AR94e8d145...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D94E8D145!AR94e8d145...

message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN",
"params":{"recordId":"001D145","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-99-4930"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Enumerate additional analytics record IDs:**

Increment `recordId` values to enumerate all BI dashboard and report records across users in the org.

## Evidence

- **HAR**: `c.CustomObjectController.getRecord` with `recordId: "001D145"` → `SUCCESS` → `SensitiveData__c: "SSN: 000-99-4930"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class CustomRecordController` (no `with sharing`) — RISK-SF-245.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-246.
- **Section 7.0**: `CustomRecord OWD: Private` — sharing rules bypassed.
- **Section 8.0**: Client-supplied `recordId` directly interpolated into SOQL.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-245):
   ```apex
   public with sharing class CustomRecordController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-246):
   ```apex
   WHERE Id = :recordId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
4. **Validate `recordId`** against user's accessible record list before querying.
5. **Whitelist allowed fields server-side**: do not accept client-supplied `fields` array.
6. **Regression test**: Apex test authenticates as User A, requests User B's `recordId` — assert `INSUFFICIENT_ACCESS` or empty `records`.
