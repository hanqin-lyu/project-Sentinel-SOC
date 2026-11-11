# P2 response SLA: suspicious activity

Sent as an attachment with every P2 Teams message from PB2.

| Item | Value |
|---|---|
| Priority | P2, Medium |
| Rule | R4 Sudo probing: sudo refused a user that is not in sudoers |
| Channel | Teams message |
| Acknowledge within | 30 minutes of incident creation |
| Resolve within | Same day |
| Automatic steps done before you read this | PB1 enrichment, PB2 P2 tag and due time comment. No block |

## What to do

1. **Acknowledge.** Open the incident in the Defender portal, assign it to yourself and set it to Active. This is the time the SLA measures.
2. **Read the evidence.** The PB1 comment (source IP score and country), the `Command` custom detail, and the auditd (`local6`) rows for the account in the same session.
3. **Decide.**
   - The user ran commands beyond probing (download, persistence, changes to accounts or keys): treat as P1. Run **PB7 Contain host**, then **PB8 Report draft** and **PB9 Close incident**.
   - Probing only, nothing changed: run **PB9 Close incident** with classification and reason.
4. **Close.** Every step above is a playbook run, so the run history and incident comments are the record. Do not change the incident or the VM by hand.

## If you miss the target

Write the reason in an incident comment. The miss shows in the Workbook; it is not hidden.
