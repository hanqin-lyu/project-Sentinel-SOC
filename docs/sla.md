# Alert priority and SLA

Every incident gets one of four priorities. The priority decides how you are told and how fast you respond.

> The targets are self-set and tested on simulated incidents. A one-person lab has no on-call rota, so this shows the scheme and the measurement work, not that a real SOC met an SLA.

| Priority | Meaning | Action | Response target | Rules |
|---|---|---|---|---|
| P1 | Likely compromise | Immediate notification and the approval card | Immediate | R2, R3 |
| P2 | Suspicious | Teams message | Within 30 minutes | R4; R5 when the threat score is high or unknown |
| P3 | Follow-up | GitHub Issue | Reviewed daily | R6 volume alert |
| P4 | Informational | Warning only (Workbook), no incident | None | R1; R5 closed automatically |

## How it works

1. **Label.** The automation rule adds P1–P4 when the incident is created, based on which rule fired. PB2 can raise a priority, never lower it.
2. **Notify.** PB7 sends the notification for that priority and writes the due time as an incident comment.
3. **Measure.** `SecurityIncident` keeps a row for every change to an incident. Time to acknowledge = first change away from `New` minus `CreatedTime`. The Workbook shows how many incidents met their target.

Each triage report records priority, due time and acknowledgement time in its header.
