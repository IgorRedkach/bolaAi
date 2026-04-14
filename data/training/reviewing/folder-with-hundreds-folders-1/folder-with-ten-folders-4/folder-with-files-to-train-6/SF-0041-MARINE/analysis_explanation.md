# Analysis Explanation

**Folder:** SF-0041-MARINE
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Platform and Architecture Review (§2.0)
HarborFlow Port API (v3.3.0) is a marine / port logistics platform on Salesforce Lightning Experience. OWD = Private on Opportunity object. Users should only access Opportunity records they own. Authorization must be enforced both via Salesforce sharing rules and explicitly in Apex using `WITH SECURITY_ENFORCED` or ownership predicates.

### 2. Apex Controller Inspection (§4.0)
`OpportunityController` is declared `public class OpportunityController` — without `with sharing`. SOQL:
```apex
SELECT Id, Name, OwnerId, SensitiveData__c, InternalNotes__c
FROM Opportunity
WHERE Id = :opportunityId
```
No `AND OwnerId = UserInfo.getUserId()`, no `WITH SECURITY_ENFORCED`. Client-supplied `opportunityId` is directly interpolated into SOQL.

### 3. Context Artifact Inconsistency
§4.0 defines the Apex method as `getOpportunityDetails(String opportunityId, ...)`. §5.0 and HAR descriptor (§6.0) both reference `c.OpportunityController.getOpportunity`. Both reference the same `OpportunityController` without sharing; the vulnerability root cause is identical. Documented as-is.

### 4. Vulnerability Pattern (§5.0)
Pattern 9.2 — SOQL and Salesforce record-level access: This pattern specifically targets Salesforce's platform-level SOQL access controls. The `without sharing` keyword negates the record-level visibility rules enforced by the Salesforce platform. Any SOQL query in this class bypasses OWD=Private, Role Hierarchy, and Sharing Rules — effectively elevating the context to a system-level query ignoring user permissions.

### 5. Risk Assessment (§8.0)
- **RISK-SF-041:** Controller without `with sharing` — OWD sharing rules bypassed.
- **RISK-SF-042:** No ownership predicate in SOQL.
- Direct `opportunityId` string interpolation into SOQL — secondary SOQL injection risk.

### 6. HAR Trace Analysis (§6.0)
- **Endpoint:** `POST https://f7e910f8.lightning.force.com/aura`
- **Auth:** `Authorization: Bearer 00DF7E910F8!ARf7e910f8...`, `X-SFDC-Session: 00DF7E910F8!ARf7e910f8...`
- **Descriptor:** `c.OpportunityController.getOpportunity`
- **Params:** `opportunityId: "00110F8"`, `fields: ["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]`
- **`aura.token: "undefined"`** — token check absent
- **Response state:** `SUCCESS`
- **Response data:** `Id: 00110F8`, `Name: Victim Opportunity Record`, `OwnerId: 005VICTIM`, `InternalNotes__c: CONFIDENTIAL: internal review notes`, `SensitiveData__c: SSN: 000-19-3181`

### 7. Marine / Port Logistics Domain Impact
Opportunity records in HarborFlow represent port service contracts, vessel scheduling agreements, and logistics arrangements. `SensitiveData__c: SSN: 000-19-3181` is a direct PII breach of port operator personnel data. Under IMO maritime security regulations and ISPS Code requirements, unauthorized access to port personnel data constitutes a security incident.

### 8. Reproduction Construction
Curl uses: host `f7e910f8.lightning.force.com`, token `00DF7E910F8!ARf7e910f8...`, descriptor `c.OpportunityController.getOpportunity`, `opportunityId: 00110F8`, full fields list. All values from §6.0 of this context.txt only.

---

**Consistency Guard:** All details (system `HarborFlow Port API`, domain `Marine/Port Logistics`, version `3.3.0`, host `f7e910f8.lightning.force.com`, token `00DF7E910F8!ARf7e910f8...`, descriptor `c.OpportunityController.getOpportunity`, `opportunityId: 00110F8`, `OwnerId: 005VICTIM`, `SSN: 000-19-3181`, RISK-SF-041, RISK-SF-042, Pattern 9.2) sourced exclusively from this folder's context.txt.
