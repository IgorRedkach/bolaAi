# Expected Response

## System
- System: ParkIQ Management API (Salesforce-Integrated) v1.1.0
- Domain: PARKING / SMART CITY
- Example ID: SF-0250
- Risk IDs: RISK-SF-250, RISK-SF-251

## Findings

### 1. Pattern 3.1 — Client-Assumed Authority: `c.ContactController.updateContact` (HAR Primary)

The Aura controller `c.ContactController.updateContact` is vulnerable to Pattern 3.1 (client-assumed authority — insecure design). The API design assumes that whatever `contactId` the client supplies is one they are authorized to access — no server-side authority verification is performed. The controller runs `without sharing` (RISK-SF-250), bypassing `OWD=Private` sharing rules, and has no ownership check in SOQL (RISK-SF-251).

Pattern 3.1 "client-assumed authority" in this context: the `updateContact` action implicitly trusts the client to only supply their own `contactId`. The insecure design flaw is that authority is assumed from the client's request rather than verified by the server against the authenticated user's identity.

**Evidence from HAR:**
- Aura action: `c.ContactController.updateContact`
- Requested `contactId`: `0019E04` — belongs to `OwnerId: "005VICTIM"`
- Response state: `SUCCESS` — server assumed the client had authority over this contact
- Response includes `SensitiveData__c: "SSN: 000-49-6519"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — SSN PII exposed in Smart City/Parking context

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.ContactController.updateContact` in the `message` POST body.
Record your own `contactId` (e.g., `001YOURCONTACTID000000`).

**Step 2 — Substitute victim `contactId` — client-assumed authority exploitation (primary HAR attack):**
```
POST https://3be99e04.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D3BE99E04!AR3be99e04...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D3BE99E04!AR3be99e04...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"0019E04","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Contact IDs:**
Salesforce Contact IDs use `003` prefix. Increment the last segment:
```
contactId: 0019E03, 0019E05, 0019E06, ...
```

**Step 4 — Verify client-assumed authority:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with:
- `SensitiveData__c: "SSN: 000-49-6519"` — SSN exposed (parking/Smart City attendee PII breach)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"`
- `OwnerId: "005VICTIM"` — client-assumed authority over another user's Contact confirmed

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-250):**
   ```apex
   public with sharing class ContactController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-251):**
   ```apex
   WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Server-side authority verification (Pattern 3.1 fix):** The server must never assume the client has authority over a resource. Always verify `contactId` belongs to the authenticated user before allowing any operation.
4. **Use `WITH SECURITY_ENFORCED` in all SOQL queries.**
5. **Automated test:** Apex test authenticating as User A requesting User B's `contactId` — assert `INSUFFICIENT_ACCESS`.
