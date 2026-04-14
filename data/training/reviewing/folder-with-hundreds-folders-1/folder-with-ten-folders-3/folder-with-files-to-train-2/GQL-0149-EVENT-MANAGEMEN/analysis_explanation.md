# Analysis Explanation
**System analysed:** VenueCore Ticketing API — GQL-0149 (Event Management / Ticketing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 6.1: Schema over-exposes `ownerId` in mutation input — misconfiguration enabling cross-tenant access.
2. HAR: `tenant-5ca2` mutates `R-2149` with `ownerId: "attacker-5ca2bbc6"` → `tenant-bbc6` data: `CONFIDENTIAL-5ca2bbc6`, `req-5ca2bbc6`.
3. Event Management: ticket inventory, attendee PII, financials — fraud and data breach risk.

## Consistency Guard
Attacker: `tenant-5ca2`. Victim: `tenant-bbc6`. Resource: `R-2149`. Sensitive: `CONFIDENTIAL-5ca2bbc6`. ownerId input: `attacker-5ca2bbc6`. Request: `req-5ca2bbc6`. All from this folder only.
