# Analysis Explanation

**Folder:** SF-0038-RAILWAY
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Platform and Architecture Review (§2.0)
RailCore Operations API (v2.0.0) is built on Salesforce Lightning Experience with an Aura Component front-end and Apex Controller back-end. The auth mechanism is a Salesforce Session ID (Bearer token). Object-level authorization is expected to be enforced via both Salesforce sharing rules (OWD = Private on Opportunity) and explicit Apex ownership checks.

### 2. Apex Controller Inspection (§4.0)
`OpportunityController` is declared `public class OpportunityController` — the absence of `with sharing` means Salesforce OWD and sharing rules are not applied to queries executed within this class. The SOQL query is:
```apex
SELECT Id, Name, OwnerId, SensitiveData__c, InternalNotes__c
FROM Opportunity
WHERE Id = :opportunityId
```
There is no `AND OwnerId = UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED`. Any valid Salesforce record ID can be substituted.

### 3. Vulnerability Pattern (§5.0)
Pattern 2.1 — Functional pivot (vertical/horizontal): The attacker uses the existing `getOpportunity` function — designed to retrieve their own records — as a pivot to access records owned by other users. No privilege escalation is required; the attacker simply substitutes a victim's `opportunityId` value.

### 4. Risk Assessment (§8.0)
Two risk items are documented:
- **RISK-SF-038:** Controller without `with sharing` — OWD=Private sharing rules bypassed.
- **RISK-SF-039:** No ownership check in SOQL WHERE clause.

### 5. HAR Trace Analysis (§6.0)
- **Endpoint:** `POST https://9d87e6c3.lightning.force.com/aura`
- **Auth headers:** `Authorization: Bearer 00D9D87E6C3!AR9d87e6c3...` and `X-SFDC-Session: 00D9D87E6C3!AR9d87e6c3...`
- **Aura action descriptor:** `c.OpportunityController.getOpportunity`
- **Params:** `opportunityId: "001E6C3"`, `fields: ["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]`
- **`aura.token: "undefined"`** — token validation is absent or bypassed
- **Response state:** `SUCCESS` — no authorization error raised
- **Response data:** `Id: 001E6C3`, `Name: Victim Opportunity Record`, `OwnerId: 005VICTIM`, `InternalNotes__c: CONFIDENTIAL: internal review notes`, `SensitiveData__c: SSN: 000-79-9573`
- The returned `OwnerId: 005VICTIM` differs from the attacker's session — this is the definitive cross-ownership evidence.

### 6. Railway/SCADA-Specific Impact
In a railway/SCADA platform, Opportunity records may represent infrastructure contracts, maintenance schedules, supplier agreements, and operational personnel data. The exposed `SensitiveData__c` field contains a Social Security Number (`SSN: 000-79-9573`) which constitutes a direct PII breach. In this domain, data exposure may also carry physical safety implications if contractor or operator identity data is compromised.

### 7. Reproduction Construction
The curl command in `expected_response.md` uses the exact HAR values from §6.0 of this context.txt: host `9d87e6c3.lightning.force.com`, token `00D9D87E6C3!AR9d87e6c3...`, Aura descriptor `c.OpportunityController.getOpportunity`, `opportunityId: 001E6C3`, and full fields list. No placeholder or cross-example data was used.

### 8. Remediation Justification
`with sharing` keyword enforcement closes the OWD bypass (RISK-SF-038). The SOQL ownership predicate + `WITH SECURITY_ENFORCED` closes RISK-SF-039. Removing the client-controlled `fields` parameter eliminates the mass-field-exposure surface (client specified all sensitive fields explicitly).

---

**Consistency Guard:** All details (system name `RailCore Operations API`, domain `Railway/SCADA`, version `2.0.0`, host `9d87e6c3.lightning.force.com`, session token `00D9D87E6C3!AR9d87e6c3...`, controller `c.OpportunityController.getOpportunity`, `opportunityId: 001E6C3`, `OwnerId: 005VICTIM`, `SSN: 000-79-9573`, RISK-SF-038, RISK-SF-039, Pattern 2.1) are sourced exclusively from this folder's context.txt.
