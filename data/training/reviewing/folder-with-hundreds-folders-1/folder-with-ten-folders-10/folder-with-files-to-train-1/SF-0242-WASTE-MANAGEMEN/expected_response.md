## System

- System: CleanRoute IoT Platform (Salesforce-Integrated) v3.8.0
- Domain: WASTE MANAGEMENT / SMART BINS
- Example ID: SF-0242
- Risk IDs: RISK-SF-242, RISK-SF-243

## Findings

### 1. Salesforce Aura BOLA on `c.LeadController.getLeadData` — Pattern 2.4 (HAR Primary)

**HAR evidence**: POST to `https://2e5ed264.lightning.force.com/aura` with action descriptor `c.LeadController.getLeadData`, param `leadId: "001D264"`. Response: `state: "SUCCESS"` with `"OwnerId": "005VICTIM"`, `"InternalNotes__c": "CONFIDENTIAL: internal review notes"`, `"SensitiveData__c": "SSN: 000-42-4623"` — victim's Lead record including SSN returned to unauthorized caller.

**Pattern 2.4 (BAC — Privilege Escalation via Parameter Tampering)**: the client substitutes the `leadId` Aura parameter with a victim record's ID. Two documented root causes (section 8.0):

- **RISK-SF-242**: `LeadController` declared without `with sharing` — Salesforce OWD (Private on Lead) and sharing rules are bypassed entirely at the Apex layer.
- **RISK-SF-243**: SOQL WHERE clause filters only by `Id = :leadId` — no `AND OwnerId = UserInfo.getUserId()` predicate. The client-supplied `leadId` is directly interpolated into dynamic SOQL without validation.

**Waste Management/Smart Bins impact**: Lead records in CleanRoute represent client accounts for waste collection services. `SensitiveData__c` contains SSNs (confirmed in HAR: `"SSN: 000-42-4623"`). `InternalNotes__c` contains internal review notes about clients. Cross-user Lead access exposes customer PII to unauthorized personnel.

## Evidence

- **HAR**: `c.LeadController.getLeadData(leadId: "001D264")` → `state: SUCCESS` → `OwnerId: 005VICTIM`, `SensitiveData__c: "SSN: 000-42-4623"`.
- **Section 4.0**: Apex `LeadController` declared without `with sharing`; SOQL has no `OwnerId` filter.
- **Section 5.0**: Pattern 2.4 — client-supplied `leadId` triggers privilege escalation.
- **Section 7.0**: Lead OWD = Private; Apex class declaration omits `with sharing`.
- **Section 8.0 (RISK-SF-242/243)**: documented risks.

## Reproduction

**Step 1 — Baseline (capture own record):**

Intercept a legitimate Aura request via Burp Suite or browser DevTools on the CleanRoute Lightning page. Record the `leadId` from your own Lead record (e.g., `001YOURLEADID000001`).

**Step 2 — Enumerate victim Lead IDs:**

Salesforce record IDs follow a predictable 18-character format with `001` prefix for Lead objects. Sequential enumeration or list API calls may discover victim `leadId` values.

**Step 3 — Substitute victim `leadId` in Aura request (primary HAR attack):**

```
POST https://2e5ed264.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D2E5ED264!AR2e5ed264...
Content-Type: application/x-www-form-urlencoded

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData",
"callingDescriptor":"UNKNOWN","params":{"leadId":"001D264",
"fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Vulnerable outcome**: `state: "SUCCESS"` with victim `OwnerId: "005VICTIM"`, `SensitiveData__c` (SSN), `InternalNotes__c` — OWD=Private bypassed.  
**Secure outcome**: `state: "ERROR"` — `INSUFFICIENT_ACCESS_OR_READONLY` error, or empty records array.

## Remediation

- **Add `with sharing` to `LeadController`** (RISK-SF-242):
  ```apex
  public with sharing class LeadController { ... }
  ```
- **Add ownership predicate to SOQL** (RISK-SF-243):
  ```apex
  WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()
  ```
- **Add `WITH SECURITY_ENFORCED`** to all SOQL queries in `LeadController`.
- **Validate `leadId` is accessible to current user** before executing SOQL (use SOQL with sharing to pre-check).
- **Regression test**: Apex test — User A requests User B's Lead `leadId` via `c.LeadController.getLeadData` — assert `INSUFFICIENT_ACCESS` or empty result.
