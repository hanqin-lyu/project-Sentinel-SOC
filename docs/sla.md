# Alert priority and SLA

Every incident and alert gets one of four priorities. The priority decides the channel and the response target.

> Targets are self-imposed and tested against simulated incidents. The lab has one analyst and no on-call rota, so results show that the scheme and its measurement work, not that a real SOC met an SLA.

## Priorities

| Priority | Meaning | Channel and action | Response target | Rules |
|---|---|---|---|---|
| P1 | Confirmed or likely compromise | Immediate notification plus the PB3 approval card | Immediate | R2, R3 |
| P2 | Suspicious, needs a look | Teams message | Within 30 minutes | R4; R5 when the enrichment score is high or unknown (incident stays open) |
| P3 | Follow-up, not urgent | GitHub Issue created | Daily response (reviewed once a day) | R6 volume alert |
| P4 | Informational | Warning only: Workbook, no incident, no notification | None | R1; R5 incidents closed automatically (counted by R6) |

## How it works

1. **Tagging.** The automation rule adds the P1–P4 label at incident creation, from the rule that fired. PB2 may raise a priority after enrichment, never lower it, and comments why.
2. **Routing.** PB7 (notify-router) reads the label and sends the notification. Channels are parameters: P2 goes to Teams (same channel as the approval cards), P3 to a GitHub Issue in this repository.
3. **Due time.** PB7 writes the priority and the response due time (UTC) as an incident comment.
4. **Breach handling.** PB7 waits until the due time, re-reads the incident, and if it is still `New` posts a breach comment and notifies again. For P1, the PB3 timeout rule also applies: no disruptive action without approval, and escalate.
5. **Measurement.** `SecurityIncident` records every change to an incident. Time to acknowledge = first change away from `New` (status or owner) minus `CreatedTime`, compared with the target for the priority label. The Workbook shows SLA met by priority, median time to acknowledge and breaches.

## Measurable definitions

| Priority | Measured as | Target |
|---|---|---|
| P1 | Time to acknowledge | Initial internal target 5 minutes, tuned from the baseline |
| P2 | Time to acknowledge | 30 minutes |
| P3 | Reviewed | Same working day |
| P4 | None | None |

## Decisions

- P2 channel: Teams (Slack dropped, to keep one chat integration).
- P3 ticket system: GitHub Issues in this repository, created by PB7.

Every triage report records priority, due time and actual acknowledgement time in its header (see `docs/triage-reports/`).
