# Analysis Explanation
**Folder:** SF-0096-HR | **Context source:** This folder's context.txt only.
- System: WageFlow Payroll API (SF), HR/Payroll Processing, OWD: Private on Opportunity
- Host: `560ea077.lightning.force.com`, token: `00D560EA077!AR560ea077...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "001A077"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-54-3034` (payroll/HR PII)
- Pattern 3.1: Client-assumed authority (Insecure Design) — system design assumes client will only supply `opportunityId` values it owns; no server-side verification; `without sharing` controller bypasses OWD=Private; attacker exploits design assumption to access any HR/payroll Opportunity record
- §8.0 RISK-SF-096/097: controller without `with sharing`; no ownership check; client-supplied `opportunityId` directly interpolated into SOQL
**Consistency Guard:** All values from this folder's context.txt only.
