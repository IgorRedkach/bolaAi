# Analysis Explanation
**Folder:** SF-0047-DOCUMENT-SIGNIN | **Context source:** This folder's context.txt only.

## Step-by-step Analysis

### 1. Platform Review (§2.0)
SignFlow eSign Platform (SF-0047), Document Signing / Legal, Salesforce Lightning. OWD = Private on Account object.

### 2. Apex Controller (§4.0)
`AccountController` — `public class AccountController` without `with sharing`. SOQL: `FROM Account WHERE Id = :accountId` — no ownership predicate.

### 3. Pattern 3.1 — Client-Assumed Authority
The design assumes the client supplies only authorised Account IDs. No server-side enforcement. The system is insecurely designed to trust the client's input rather than verify it.

### 4. HAR (§6.0)
- Host: `df454b7e.lightning.force.com`, token: `00DDF454B7E!ARdf454b7e...`
- Descriptor: `c.AccountController.getAccounts`, `accountId: "0014B7E"`
- Response: `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-35-5627`
- RISK-SF-047, RISK-SF-048

### 5. Document Signing Domain Impact
eSign Account records represent legal signing parties. SSN exposure and `internalNotes` access may reveal privileged legal communications and signatory identity data with serious legal consequences.

**Consistency Guard:** system `SignFlow eSign Platform`, host `df454b7e.lightning.force.com`, token `00DDF454B7E!ARdf454b7e...`, `accountId: 0014B7E`, `SSN: 000-35-5627`, RISK-SF-047/048, Pattern 3.1 — from this folder's context.txt only.
