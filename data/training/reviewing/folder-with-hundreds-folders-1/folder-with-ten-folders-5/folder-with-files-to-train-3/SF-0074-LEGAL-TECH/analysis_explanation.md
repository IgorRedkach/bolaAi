# Analysis Explanation
**Folder:** SF-0074-LEGAL-TECH | **Context source:** This folder's context.txt only.
- System: LexVault eDiscovery API, Legal Tech/eDiscovery, OWD: Private on Opportunity
- Host: `aa59f255.lightning.force.com`, token: `00DAA59F255!ARaa59f255...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "001F255"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-87-5782`
- Pattern 2.4: Privilege escalation via parameter tampering — attacker reads victim's eDiscovery Opportunity records
**Consistency Guard:** All values from this folder's context.txt only.
