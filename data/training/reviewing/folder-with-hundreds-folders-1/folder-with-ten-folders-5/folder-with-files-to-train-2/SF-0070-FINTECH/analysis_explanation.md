# Analysis Explanation
**Folder:** SF-0070-FINTECH | **Context source:** This folder's context.txt only.
- System: PayBridge Transaction API, FinTech/Payment, OWD: Private on Opportunity
- Host: `be5b5c9d.lightning.force.com`, token: `00DBE5B5C9D!ARbe5b5c9d...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "0015C9D"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-75-5143`
- Pattern 10.2: Parameter escalation — attacker extends own session scope to Opportunity records they don't own
**Consistency Guard:** All values from this folder's context.txt only.
