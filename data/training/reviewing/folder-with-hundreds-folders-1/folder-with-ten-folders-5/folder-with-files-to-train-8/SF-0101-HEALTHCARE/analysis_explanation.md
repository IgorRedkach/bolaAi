# Analysis Explanation
**Folder:** SF-0101-HEALTHCARE | **Context source:** This folder's context.txt only.
- System: PatientCore EHR API (SF), Healthcare/EHR Platform, OWD: Private on Opportunity
- Host: `809bb9e4.lightning.force.com`, token: `00D809BB9E4!AR809bb9e4...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "001B9E4"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-46-7904` — PHI in healthcare context, HIPAA violation risk
- Pattern 2.1: Functional pivot (vertical/horizontal) (BAC) — attacker pivots to the Opportunity controller (originally designed for CRM not PHI access) to read patient EHR-associated records; controller lacks ownership check; `without sharing` bypasses OWD=Private
- §8.0 RISK-SF-101/102: controller without `with sharing`; no ownership check; client-supplied `opportunityId` directly interpolated
- HIPAA context: SSN exposure in EHR system = Protected Health Information (PHI) breach
**Consistency Guard:** All values from this folder's context.txt only.
