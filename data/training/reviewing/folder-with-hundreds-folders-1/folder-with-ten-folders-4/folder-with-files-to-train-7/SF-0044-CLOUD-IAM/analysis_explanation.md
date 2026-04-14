# Analysis Explanation

**Folder:** SF-0044-CLOUD-IAM
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Platform Review (§2.0)
VaultGuard IAM API (SF-0044) is a Cloud IAM platform on Salesforce Lightning. OWD = Private on Opportunity object.

### 2. Apex Controller (§4.0)
`OpportunityController` declared `public class OpportunityController` — without `with sharing`. SOQL: `FROM Opportunity WHERE Id = :opportunityId` — no ownership predicate.

### 3. Pattern 1.12 — Mass Assignment via Object Fields
The client supplies a `fields` array `["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]`. The controller returns all requested fields without validation. This is mass assignment: the attacker controls which sensitive fields are returned.

### 4. HAR (§6.0)
- Host: `2c2cbec7.lightning.force.com`, token: `00D2C2CBEC7!AR2c2cbec7...`
- Descriptor: `c.OpportunityController.getOpportunity`, `opportunityId: "001BEC7"`
- Response: `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-25-3062`
- RISK-SF-044 (no `with sharing`), RISK-SF-045 (no ownership predicate)

### 5. Cloud IAM Domain Impact
IAM Opportunity records may represent access provisioning agreements and identity federation scopes. Exposure of `SensitiveData__c` containing SSN data constitutes a direct PII breach of IAM operator personnel.

---
**Consistency Guard:** system `VaultGuard IAM API`, host `2c2cbec7.lightning.force.com`, token `00D2C2CBEC7!AR2c2cbec7...`, `opportunityId: 001BEC7`, `SSN: 000-25-3062`, RISK-SF-044/045, Pattern 1.12 — all from this folder's context.txt only.
