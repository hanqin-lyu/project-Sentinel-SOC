# 14-day schedule

About 18–20 hours a week. The honeypot collects from day 2 while automation is built in vertical slices; tests use attacker-sim.

| Phase | Days | Exit criteria |
|---|---|---|
| 0 Foundation and de-risking | 1 | Terraform applied; budget alerts; Teams connector and managed-identity spikes pass |
| 1 Honeypot and collection | 2–3 | Real SSH attacks in Syslog; filters and daily cap set (48 h ingestion review on days 4–5, in parallel) |
| 2 Detection | 3–5 | R1, R2, R3, R5 firing (R4 optional); entity mapping, Trusted_IPs, attacker-sim |
| 3+4 Automation | 5–10 | A (5–6): labels, PB1, PB2, block with TTL. B (7–8): PB3 approval, Run Command session kill. C (9–10): PB4, PB5, PB7 routing |
| 5 Measurement and evidence | 9–12 | Workbook (SLA by priority, success rate, time to contain); core test matrix; R5 auto-close + R6 email; minimal PB6 |
| 5b Triage reports | 10–12 | TR-001, TR-002 filled with real data |
| 6 Delivery | 13–14 | README, screenshots, demo, honeypot RG destroyed; day 14 buffer |

## Cut or deferred
PB7 breach re-check, R4 (optional), tests for threat-intel API failure, private/already-blocked IP and P1 breach reminder.

## Core test matrix
High-score full chain; approval denied; approval timeout; low score no block; Trusted_IPs; kill-switch off; TTL expiry; R5 auto-close with R6 email; established session survives an NSG change.

## Tip
Run playbooks manually on an incident first; attach the automatic trigger afterwards (analytics rules run at most every 5 minutes, plus ingestion delay).
