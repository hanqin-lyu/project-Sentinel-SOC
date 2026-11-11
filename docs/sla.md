# Alert priority and SLA

Every incident gets one of four priorities. The priority decides how you are told and how fast you respond.

> The targets are self-set and tested on simulated incidents. A one-person lab has no on-call rota, so this shows the scheme and the measurement work, not that a real SOC met an SLA.

| Priority | Meaning | Action | Response target | Rules |
|---|---|---|---|---|
| P1 | Likely compromise | Teams message; IP blocked automatically; analyst runs the containment playbook | Immediate | R2 Compromise after brute force |
| P2 | Suspicious | Teams message with [P2 SLA](sla/P2-sla.md) attached | Within 30 minutes | R4 Sudo probing |
| P3 | Follow-up | Teams message with [P3 SLA](sla/P3-sla.md) attached | Reviewed daily | R5 Sustained brute force |
| P4 | Informational | Alert only (Workbook), no incident | None | R1 SSH brute force |

## How it works

1. **Label and notify.** When the incident is created, the rule's automation rule starts its notify playbook (PB4 for P1, PB2 for P2, PB3 for P3), which adds the P tag, sends the Teams message and, for P2 and P3, writes the due time and attaches the SLA file.
2. **Respond.** Every later step is a playbook (see the Playbooks section of `README.md`), so the incident's comments and the playbook run history show what was done and when.
3. **Measure.** `SecurityIncident` keeps a row for every change to an incident. Time to acknowledge = first change away from `New` minus `CreatedTime`. The Workbook shows how many incidents met their target.

Each triage report records priority, due time and acknowledgement time in its header.
