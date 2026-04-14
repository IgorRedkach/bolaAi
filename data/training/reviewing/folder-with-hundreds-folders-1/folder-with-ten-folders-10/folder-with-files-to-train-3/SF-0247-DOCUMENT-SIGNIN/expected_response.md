# Expected Response

## System
- System: SignFlow eSign Platform (Salesforce-Integrated) v4.9.0
- Domain: DOCUMENT SIGNING / eSIGN
- Example ID: SF-0247
- Risk IDs: RISK-SF-247, RISK-SF-248

## Findings

### 1. Pattern 1.12 — Mass Assignment via Client-Supplied `fields` Array + BOLA: `c.OpportunityController.getOpportunity` (HAR Primary)

The Aura controller `c.OpportunityController.getOpportunity` accepts both `opportunityId` (cross-tenant ID substitution) and a client-controlled `fields` array specifying which Opportunity fields to return. The controller runs `without sharing` (RISK-SF-247), bypassing `OWD=Private` sharing rules, and contains no ownership check in the SOQL WHERE clause (RISK-SF-248). This enables two compounding vulnerabilities:

1. **BOLA:** Any `opportunityId` can be substituted to read another user's Opportunity record.
2. **Mass assignment (Pattern 1.12):** The client specifies the exact fields returned including sensitive custom fields `SensitiveData__c` and `InternalNotes__c`, bypassing field-level security that would otherwise restrict access to these fields.

**Evidence from HAR:**
- Aura action: `c.OpportunityController.getOpportunity`
- Requested `opportunityId`: `001C988` — belongs to `OwnerId: "005VICTIM"`
- Client-supplied `fields`: `["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response state: `SUCCESS` — no authorization error
- Response includes `SensitiveData__c: "SSN: 000-52-7113"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — PII exposed

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.OpportunityController.getOpportunity` in the `message` POST body.
Record your own `opportunityId` (e.g., `001YOURRECORDID000000`).

**Step 2 — Substitute victim `opportunityId` + mass assign sensitive fields (primary HAR attack):**
```
POST https://c4dfc988.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DC4DFC988!ARc4dfc988...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DC4DFC988!ARc4dfc988...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001C988","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Opportunity IDs:**
Salesforce Opportunity IDs follow predictable patterns (18-char with `001` prefix). Increment the last segment to enumerate victim records:
```
opportunityId: 001C987, 001C989, 001C98A, ...
```

**Step 4 — Verify BOLA + mass assignment:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim Opportunity data including:
- `SensitiveData__c: "SSN: 000-52-7113"` — SSN exposed (PII breach)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"`
- `OwnerId: "005VICTIM"` — confirmed cross-user access

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-247):**
   ```apex
   public with sharing class OpportunityController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-248):**
   ```apex
   WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries** to enforce field-level security server-side, preventing client-supplied `fields` from bypassing FLS.
4. **Server-side field allowlist:** Do not accept `fields` parameter from client. Define the allowed fields server-side only.
5. **Automated test:** Apex test authenticating as User A requesting User B's `opportunityId` — assert `INSUFFICIENT_ACCESS` or empty result.
