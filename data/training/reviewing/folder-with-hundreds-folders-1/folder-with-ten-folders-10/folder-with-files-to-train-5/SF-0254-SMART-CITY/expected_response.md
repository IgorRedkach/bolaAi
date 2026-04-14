# Expected Response

## System
- System: MetroPulse Traffic Orchestration (Salesforce-Integrated) v4.0.0
- Domain: SMART CITY / TRAFFIC MANAGEMENT
- Example ID: SF-0254
- Risk IDs: RISK-SF-254, RISK-SF-255

## Findings

### 1. Pattern 1.12 — Mass Assignment via Client-Controlled `fields` Array: `c.LeadController.getLeadData` (HAR Primary)

The Aura controller `c.LeadController.getLeadData` accepts two client-controlled parameters: `leadId` and `fields`. Pattern 1.12 "mass assignment via object fields" — the client supplies a list of field names in the `fields` array, which the controller concatenates directly into the SOQL SELECT clause without validating Field Level Security (FLS) per field. Fields like `SensitiveData__c` and `InternalNotes__c` are restricted to Admin profile in Salesforce FLS (Section 7.0), but a non-admin caller can include them in the `fields` array and receive their values.

Combined with the `without sharing` declaration (RISK-SF-254) and missing `OwnerId` predicate (RISK-SF-255), an authenticated user can access any Lead record and include any field — including FLS-restricted ones.

**Evidence from HAR:**
- Aura action: `c.LeadController.getLeadData`
- `leadId: "0019678"` — belongs to `OwnerId: "005VICTIM"` (cross-user access)
- `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]` — FLS-restricted fields included in client request
- Response state: `SUCCESS` — FLS and ownership checks both bypassed
- Response includes `SensitiveData__c: "SSN: 000-77-6053"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — FLS-restricted fields returned

In Smart City / Traffic Management, Lead records represent municipal service requests, citizen data, and smart infrastructure contact details. FLS bypass exposes citizen SSN and internal government notes.

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request. Identify `c.LeadController.getLeadData` in the `message` POST body. Note the `fields` array in use.

**Step 2 — Mass assignment: add FLS-restricted fields to `fields` array (primary HAR attack):**
```
POST https://43649678.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D43649678!AR43649678...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D43649678!AR43649678...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"0019678","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```
**Vulnerable outcome:** `SensitiveData__c: "SSN: 000-77-6053"` returned despite FLS restriction — mass assignment of restricted fields confirmed.

**Step 3 — Add additional restricted fields to mass assignment:**
```
"fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c", "Email", "Phone", "BirthDate__c"]
```
Any field on the Lead object can be included, including hidden audit fields and custom restricted fields.

**Step 4 — Cross-user BOLA: substitute another user's `leadId` (RISK-SF-254, RISK-SF-255):**
```
"leadId": "0019677"  # or 0019679, 0019680 ...
```
Combines cross-user ID access with mass assignment for maximum data exposure.

**Step 5 — Verify bypass:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with `SensitiveData__c` and `InternalNotes__c` from another user's Lead record — both FLS and record ownership bypassed.

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records`.

## Remediation
1. **Validate each field in `fields` against FLS before building SELECT:**
   ```apex
   for (String field : fields) {
     Schema.DescribeFieldResult dfr = Lead.SObjectType.getDescribe().fields.getMap().get(field).getDescribe();
     if (!dfr.isAccessible()) throw new AuraHandledException('Field access denied: ' + field);
   }
   ```
2. **Add `with sharing` to Apex class (RISK-SF-254):** `public with sharing class LeadController { ... }`
3. **Add ownership filter to SOQL (RISK-SF-255):** `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()`
4. **Use `WITH SECURITY_ENFORCED`** to enforce field-level security at query level.
5. **Allowlist permitted fields** — never build dynamic SELECT from unchecked client input.
