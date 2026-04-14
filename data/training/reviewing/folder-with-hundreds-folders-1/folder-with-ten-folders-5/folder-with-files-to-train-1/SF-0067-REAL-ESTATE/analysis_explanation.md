# Analysis Explanation
**Folder:** SF-0067-REAL-ESTATE | **Context source:** This folder's context.txt only.
- System: EstateFlow Property API, Real Estate/PropTech, OWD: Private on Opportunity
- Host: `1fd8fc4d.lightning.force.com`, token: `00D1FD8FC4D!AR1fd8fc4d...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "001FC4D"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-65-3257`
- Pattern 2.4: Privilege escalation via parameter tampering — attacker tampers `opportunityId` to read victim's property deal records.
**Consistency Guard:** All values from this folder's context.txt only.
