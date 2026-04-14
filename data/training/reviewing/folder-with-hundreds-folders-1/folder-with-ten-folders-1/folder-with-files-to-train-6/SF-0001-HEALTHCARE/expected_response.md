## System

- System: PatientCore EHR API (Salesforce-Integrated) v1.6.0
- Domain: HEALTHCARE / EHR PLATFORM
- Example ID: SF-0001
- Risk IDs: RISK-SF-001, RISK-SF-002

## Findings

### 1. Salesforce Aura BOLA — Apex Controller Without Sharing, No Ownership Check (Pattern 1.5)

The Aura controller action `c.QuoteController.getQuoteDetails` exposes a `quoteId` parameter in the Aura request payload. The Apex class is declared `public class QuoteController` without `with sharing` (RISK-SF-001). The SOQL query filters only by ID:

```apex
'FROM Quote WHERE Id = :' + quoteId
// Missing: AND OwnerId = UserInfo.getUserId()
// Missing: WITH SECURITY_ENFORCED
```

The Quote object's OWD is `Private` (section 7.0) — sharing rules prevent standard Salesforce record access. However, because the controller runs `without sharing`, Salesforce's sharing enforcement is bypassed entirely. The attacker's authenticated session is valid, but they are never the owner of the requested `quoteId`.

**HAR evidence**: Aura `POST /aura` with session token `00DA389E8E7!...`. Request action descriptor: `c.QuoteController.getQuoteDetails`. Injected `quoteId: "001E8E7"` (belongs to `OwnerId: 005VICTIM`). Response state: `SUCCESS`. Response body includes `"InternalNotes__c": "CONFIDENTIAL: internal review notes"` and `"SensitiveData__c": "SSN: 000-28-7184"` — a patient's Social Security Number returned to an unauthorized caller.

**Healthcare impact**: `SensitiveData__c` contains `SSN: 000-28-7184` — a Social Security Number is PHI under HIPAA. `InternalNotes__c` contains `CONFIDENTIAL: internal review notes`. Cross-user access to PHI in an EHR platform constitutes a HIPAA breach.

## Evidence

- **Section 4.0** (Apex code): `public class QuoteController` — no `with sharing`; SOQL `WHERE Id = :quoteId` — no `OwnerId` predicate; missing `WITH SECURITY_ENFORCED`.
- **Section 7.0**: Quote OWD = Private; Apex class declared without `with sharing`.
- **RISK-SF-001**: controller declared `without sharing` — sharing rules not enforced.
- **RISK-SF-002**: no ownership check in SOQL WHERE clause.
- **HAR**: attacker JWT → `c.QuoteController.getQuoteDetails(quoteId: "001E8E7")` → HTTP 200 → `state: SUCCESS` → response includes `SensitiveData__c: SSN: 000-28-7184` and `InternalNotes__c: CONFIDENTIAL`.

## Reproduction

**Step 1 — Capture a baseline Aura request to your own record:**

Intercept a legitimate Aura request via Burp Suite or browser DevTools. Identify the `c.QuoteController.getQuoteDetails` action in the `message` POST body. Record your own `quoteId`.

**Step 2 — Substitute victim `quoteId`:**

```
POST https://a389e8e7.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DA389E8E7!ARa389e8e7...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA389E8E7!ARa389e8e7...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"001E8E7","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure outcome: response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records`.  
Expected vulnerable outcome: HTTP 200, `state: "SUCCESS"`, response body with victim's `SensitiveData__c` (SSN) and `InternalNotes__c`.

**Step 3 — Enumerate records (amplification):**

Salesforce record IDs have a 3-character prefix and follow a predictable alphanumeric pattern. Enumerate `quoteId` values with the `001` prefix using batched Aura requests to discover additional patient Quote records.

## Remediation

- **Add `with sharing` to Apex class declaration** (RISK-SF-001):
  ```apex
  public with sharing class QuoteController { ... }
  ```
- **Add `OwnerId` ownership filter to SOQL** (RISK-SF-002):
  ```apex
  'FROM Quote WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()'
  ```
- **Add `WITH SECURITY_ENFORCED` to all SOQL queries** to enforce field-level security.
- **Validate `quoteId` against accessible record IDs**: use `WITH SHARING` + SOQL check before executing the main query.
- **Automated regression test**: write an Apex test that authenticates as User A and requests User B's Quote ID — assert `AuraHandledException` or empty result.
