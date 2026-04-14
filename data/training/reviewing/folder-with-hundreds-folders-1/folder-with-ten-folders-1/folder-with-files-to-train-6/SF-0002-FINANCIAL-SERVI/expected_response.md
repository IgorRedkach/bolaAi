## System

- System: NexaBank Open Finance API (Salesforce-Integrated) v1.2.0
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: SF-0002
- Risk IDs: RISK-SF-002, RISK-SF-003

## Findings

### 1. Salesforce Aura BOLA — Apex Controller Without Sharing, No Ownership Check (Pattern 1.12)

The Aura controller action `c.ContactController.updateContact` exposes a `contactId` parameter in the Aura request payload. The Apex class is declared `public class ContactController` without `with sharing` (RISK-SF-002). The SOQL query in `getContactDetails` filters only by ID:

```apex
'FROM Contact WHERE Id = :' + contactId
// Missing: AND OwnerId = UserInfo.getUserId()
// Missing: WITH SECURITY_ENFORCED
```

The Contact object's OWD is `Private` (section 7.0) — standard Salesforce sharing enforcement should prevent cross-user record access. The `without sharing` declaration bypasses this entirely. Section 5.0 notes: client-supplied `contactId` is directly interpolated into SOQL without validation.

**HAR evidence**: Aura `POST /aura` to `7688efe9.lightning.force.com` with session token `00D7688EFE9!...`. Request action descriptor: `c.ContactController.updateContact`. Injected `contactId: "001EFE9"` (belongs to `OwnerId: 005VICTIM`). Response state: `SUCCESS`. Response body: `"InternalNotes__c": "CONFIDENTIAL: internal review notes"` and `"SensitiveData__c": "SSN: 000-71-5059"` — victim's Social Security Number returned to the attacker.

**Financial services impact**: the Contact object in a retail banking Salesforce org contains customer contact details, credit inquiry notes, and relationship manager annotations. `SensitiveData__c` with SSN constitutes GLBA-protected customer financial information. Cross-user access is a regulatory violation.

## Evidence

- **Section 4.0** (Apex code): `public class ContactController` — no `with sharing`; SOQL `WHERE Id = :contactId` — no `OwnerId` predicate; missing `WITH SECURITY_ENFORCED`.
- **Section 7.0**: Contact OWD = Private; controller without `with sharing`.
- **RISK-SF-002**: controller without sharing — sharing rules not enforced.
- **RISK-SF-003**: no ownership check in SOQL.
- **HAR**: attacker JWT → `c.ContactController.updateContact(contactId: "001EFE9")` → HTTP 200 → `state: SUCCESS` → `SensitiveData__c: SSN: 000-71-5059`.

## Reproduction

**Step 1 — Capture a baseline Aura request to your own Contact record:**

Intercept a legitimate Aura request via Burp Suite or browser DevTools. Identify the `c.ContactController.updateContact` action in the `message` POST body. Record your own `contactId`.

**Step 2 — Substitute victim `contactId` (primary HAR attack):**

```
POST https://7688efe9.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D7688EFE9!AR7688efe9...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7688EFE9!AR7688efe9...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001EFE9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure outcome: response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records`.  
Expected vulnerable outcome: HTTP 200, `state: "SUCCESS"`, response with `SensitiveData__c: SSN: 000-71-5059`.

**Step 3 — Enumerate Contact records:**

Salesforce Contact IDs use a `003` prefix (standard Contact key prefix). Enumerate `contactId` values starting with `003` + sequential characters to discover additional victim records.

## Remediation

- **Add `with sharing` to Apex class** (RISK-SF-002):
  ```apex
  public with sharing class ContactController { ... }
  ```
- **Add `OwnerId` filter to SOQL** (RISK-SF-003):
  ```apex
  'FROM Contact WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()'
  ```
- **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
- **Remove `contactId` from mass-update surface**: validate client-supplied IDs against `[SELECT Id FROM Contact WHERE OwnerId = :UserInfo.getUserId()]` before any query.
- **Automated regression test**: authenticate as User A, request User B's Contact ID — assert `AuraHandledException` or empty result.
