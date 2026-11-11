# P3 response SLA: follow-up

Sent as an attachment with every P3 Teams message from PB3.

| Item | Value |
|---|---|
| Priority | P3, Low |
| Rule | R5 Sustained brute force: 50 or more failed SSH logins from one IP in 10 minutes, no successful login in 24 hours |
| Channel | Teams message |
| Acknowledge within | The next daily review |
| Resolve within | Same day as the review |
| Automatic steps done before you read this | PB1 enrichment, PB3 P3 tag and due time comment. No block |

## What to do

1. **Acknowledge.** At the daily review, open the incident, assign it to yourself and set it to Active.
2. **Check for a login.** Confirm there is still no `Accepted` login from the source IP. If there is one, R2 raises a P1 incident; follow that one and link the two.
3. **Read the evidence.** The PB1 comment (score, country), failed count and usernames tried.
4. **Close.** Run **PB9 Close incident**, usually as Benign Positive (expected Internet scanning), and note any follow-up (threshold tuning, watchlist entry) in the closing comment.

## If you miss the target

Write the reason in an incident comment. The miss shows in the Workbook; it is not hidden.
