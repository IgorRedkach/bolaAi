# Expected Response

## System
- Domain: Legal Tech / Document Management
- System: LexVault eDiscovery API (Salesforce-Integrated)
- Example ID: SF-0124

## Priority Findings

### Finding 1: Salesforce Aura BOLA — Client-assumed authority (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design
**OWASP API:** API1:2023 Broken Object Level Authorization

**Summary:**
The Salesforce Aura controller action `c.ContactController.updateContact` is vulnerable to Pattern 3.1.
The Apex controller is declared `without sharing` and performs no ownership validation.
An authenticated user can substitute any `contactId` value in the Aura framework
`POST /aura` request payload to read records owned by other users.

**Evidence from HAR:**
- Aura action: `c.ContactController.updateContact`
- Requested `contactId`: `0010B23` (belongs to a different user)
- Response state: `SUCCESS` — no authorization error
- Response body includes `SensitiveData__c` and `InternalNotes__c` belonging to another user
- The session user's `OwnerId` does not match the returned record's `OwnerId`

**Root Cause:**
1. Apex class declared `without sharing` — Salesforce OWD/sharing rules are bypassed
2. SOQL query filters only by `contactId` — no `AND OwnerId = UserInfo.getUserId()` predicate
3. `contactId` sourced directly from Aura params without server-side validation

## Steps to Reproduce

### Step 1 — Capture a baseline Aura request to your own record
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify the `c.ContactController.updateContact` action in the `message` POST body.
Record your own `contactId` value (e.g., `001YOURRECORDID000000`).

### Step 2 — Enumerate or guess victim record IDs
Salesforce record IDs follow a predictable 18-character pattern with a 3-char prefix.
Use the list endpoint or sequential enumeration to discover victim `contactId` values.

### Step 3 — Substitute victim ID in Aura request
```
POST https://<ORG_ID>.lightning.force.com/aura HTTP/1.1
Authorization: Bearer <YOUR_SESSION_TOKEN>
Content-Type: application/x-www-form-urlencoded

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"0010B23","fields":["Id","Name","OwnerId","SensitiveData__c","InternalNotes__c"]}}]}
&aura.token=undefined
```

### Step 4 — Verify BOLA
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim record data including
`SensitiveData__c` and `InternalNotes__c`. The `OwnerId` in the response will differ
from your authenticated user ID.

**Secure outcome:** Response `state: "ERROR"` with an authorization message, or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class declaration:**
   ```apex
   public with sharing class ContactController { ... }
   ```
2. **Add ownership filter to SOQL:**
   ```apex
   WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries.**
4. **Validate `contactId` against the user's accessible record IDs before querying.**
5. **Automated test:** Write a Salesforce Apex test that authenticates as User A and requests User B's record ID — assert INSUFFICIENT_ACCESS or empty result.
