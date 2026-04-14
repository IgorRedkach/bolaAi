# Expected Response

## System
- System: TaxGrid Compliance API (Salesforce-Integrated) v1.7.0
- Domain: TAX COMPLIANCE / REGTECH
- Example ID: SF-0248
- Risk IDs: RISK-SF-248, RISK-SF-249

## Findings

### 1. Pattern 2.1 — Functional Pivot (Horizontal): `c.ContactController.updateContact` (HAR Primary)

The Aura controller `c.ContactController.updateContact` is vulnerable to Pattern 2.1 (functional pivot). The attacker pivots the Contact read/update function horizontally across user boundaries — using their valid session to access Contact records owned by other users. The controller runs `without sharing` (RISK-SF-248), bypassing `OWD=Private` on the Contact object, and the SOQL WHERE clause filters only by `contactId` with no ownership check (RISK-SF-249).

This is a BAC (Broken Access Control) functional pivot: the `updateContact` action is intended to operate on the authenticated user's own Contact record. By substituting `contactId`, the attacker pivots the function to operate on any other user's Contact record, including their sensitive PII and tax compliance data.

**Evidence from HAR:**
- Aura action: `c.ContactController.updateContact`
- Requested `contactId`: `001BCE9` — belongs to `OwnerId: "005VICTIM"`
- Response state: `SUCCESS` — no authorization error
- Response includes `SensitiveData__c: "SSN: 000-61-8487"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — SSN PII exposed in Tax Compliance context

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.ContactController.updateContact` in the `message` POST body.
Record your own `contactId` (e.g., `001YOURCONTACTID000000`).

**Step 2 — Substitute victim `contactId` — functional pivot (primary HAR attack):**
```
POST https://9532bce9.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D9532BCE9!AR9532bce9...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D9532BCE9!AR9532bce9...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"001BCE9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Contact IDs:**
Salesforce Contact IDs follow predictable patterns (`003` prefix for Contact object). Increment the last segment:
```
contactId: 001BCE8, 001BCEA, 001BCEB, ...
```

**Step 4 — Verify functional pivot:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim Contact data including:
- `SensitiveData__c: "SSN: 000-61-8487"` — SSN exposed (tax compliance PII breach)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"`
- `OwnerId: "005VICTIM"` — confirmed cross-user access

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-248):**
   ```apex
   public with sharing class ContactController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-249):**
   ```apex
   WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries.**
4. **Server-side field allowlist:** Define allowed fields server-side; do not accept `fields` parameter from client.
5. **Automated test:** Apex test authenticating as User A requesting User B's `contactId` — assert `INSUFFICIENT_ACCESS` or empty result.
