# Analysis Explanation

This example (SF-0141) was generated independently for **HarborFlow Port API** (Marine / Port Logistics).

## Generation Method
1. Selected industry: **Marine / Port Logistics**
2. Designed Salesforce Lightning Aura architecture with Apex controller.
3. Embedded **Pattern 1.5 (Multi-tenant / cross-tenant access)** via `without sharing` and missing WHERE predicate.
4. Generated HAR capture of the Aura framework `POST /aura` request with injected victim ID.
5. Wrote expected response grounded exclusively in this example's context.txt.

## Why Salesforce Aura?
Aura framework requests are serialized `POST /aura` messages with a `message` field containing
JSON-encoded actions. The `contactId` inside the `params` object is fully attacker-controlled.
Without server-side ownership validation in the Apex controller, any record ID can be queried.

## Consistency Guard
- No context from other examples was used.
- All record IDs and session tokens are unique to this folder.

## Pattern Coverage
- Primary: Pattern 1.5 — Multi-tenant / cross-tenant access (BOLA)
