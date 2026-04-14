## System

- System: NeoBuild BAS Platform (Salesforce-Integrated) v4.0.0
- Domain: SMART HOME / BUILDING AUTOMATION
- Example ID: SF-0243
- Risk IDs: RISK-SF-243, RISK-SF-244

## Findings

### 1. Salesforce Aura BOLA on `c.ContactController.updateContact` — Pattern 3.1 (HAR Primary)

**HAR evidence**: POST to `https://4347eb34.lightning.force.com/aura` with action descriptor `c.ContactController.updateContact`, param `contactId: "001EB34"`. Response: `state: "SUCCESS"` with `"OwnerId": "005VICTIM"`, `"InternalNotes__c": "CONFIDENTIAL: internal review notes"`, `"SensitiveData__c": "SSN: 000-79-1437"` — victim's Contact record including SSN returned to unauthorized caller.

**Pattern 3.1 (Insecure Design — Client-Assumed Authority)**: the client assumes they have authority to update any Contact record by supplying its ID. The application design delegates authorization to the client — there is no server-side check confirming the caller owns or has rights to the requested `contactId`. Two documented root causes (section 8.0):

- **RISK-SF-243**: `ContactController` declared without `with sharing` — Contact OWD=Private and sharing rules are bypassed.
- **RISK-SF-244**: SOQL WHERE clause has no `AND OwnerId = UserInfo.getUserId()` predicate.

**Smart Home/Building Automation impact**: Contact records in NeoBuild BAS represent building residents, facility managers, or service contacts. `SensitiveData__c` contains SSNs (confirmed in HAR: `SSN: 000-79-1437`). The `updateContact` write action means an attacker with a valid session can also modify another resident's Contact record fields.

## Evidence

- **HAR**: `c.ContactController.updateContact(contactId: "001EB34")` → `state: SUCCESS` → `OwnerId: 005VICTIM`, `SensitiveData__c: "SSN: 000-79-1437"`.
- **Section 4.0**: `ContactController` declared without `with sharing`; SOQL has no `OwnerId` filter.
- **Section 5.0**: Pattern 3.1 — client assumes authority to update Contact via `contactId`.
- **Section 7.0**: Contact OWD = Private; Apex class omits `with sharing`.
- **Section 8.0 (RISK-SF-243/244)**: documented risks.

## Reproduction

**Step 1 — Baseline (capture own contact):**

Intercept a legitimate Aura request on the NeoBuild Lightning page. Identify the `c.ContactController.updateContact` action and record your own `contactId`.

**Step 2 — Enumerate victim Contact IDs:**

Contact object IDs have a `001` prefix in 18-character Salesforce ID format. Sequential enumeration may discover victim `contactId` values.

**Step 3 — Substitute victim `contactId` in Aura request (primary HAR attack):**

```
POST https://4347eb34.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D4347EB34!AR4347eb34...
Content-Type: application/x-www-form-urlencoded

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact",
"callingDescriptor":"UNKNOWN","params":{"contactId":"001EB34",
"fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Vulnerable outcome**: `state: "SUCCESS"` with victim `OwnerId: "005VICTIM"`, `SensitiveData__c` (SSN), `InternalNotes__c` — OWD=Private bypassed.  
**Secure outcome**: `state: "ERROR"` — `INSUFFICIENT_ACCESS_OR_READONLY` or empty records.

## Remediation

- **Add `with sharing` to `ContactController`** (RISK-SF-243):
  ```apex
  public with sharing class ContactController { ... }
  ```
- **Add ownership predicate to SOQL** (RISK-SF-244):
  ```apex
  WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()
  ```
- **Add `WITH SECURITY_ENFORCED`** to all SOQL in `ContactController`.
- **Regression test**: Apex test — User A requests User B's Contact `contactId` via `c.ContactController.updateContact` — assert `INSUFFICIENT_ACCESS` or empty result.
