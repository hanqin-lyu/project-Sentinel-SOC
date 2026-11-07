# Playbooks

Logic Apps playbooks for Microsoft Sentinel, kept as code. The aim is no loose scripts: every automated action is a playbook or automation rule listed here.

## Conventions

1. **Single responsibility.** One playbook, one job. A step that needs no external call belongs in a Sentinel automation rule, not a Logic App.
2. **Settings are parameters, not copies.** Kill switch, block TTL, approval timeout, score threshold and similar values are template parameters. Change behaviour by changing a parameter, never by duplicating a playbook.
3. **Playbooks are code.** Each playbook folder holds an ARM template (`azuredeploy.json`), an example parameter file (`azuredeploy.parameters.example.json`) and a `README.md` based on `_template/README.md`.
4. **No secrets in templates.** Use managed identity for Azure calls and Key Vault or an API connection for third-party keys. Real parameter files are named `*.parameters.local.json` and are git-ignored.
5. **Least privilege.** The README of each playbook lists the exact roles its identity needs and their scope.
6. **Tested before listed.** A playbook is added to the index only after its test cases in the README have been run.

## Index

| ID | Playbook | Trigger | Responsibility | Status |
|---|---|---|---|---|
| PB1 | Enrichment | Incident (automation rule) | Query threat intelligence for the attacker IP; write the result to an incident comment | [planned] |
| PB2 | Containment decision | Incident (after PB1) | Branch on score and severity: automatic block, auto-close low risk, or leave for review | [planned] |
| PB3 | Approval | Called by PB2 | Approve/Deny card for session kill and account lock; act on the response | [planned] |
| PB4 | Block expiry | Schedule | Remove blocks older than the TTL | [planned] |
| PB5 | Failure handler | Called on failure | Comment on the incident and notify | [planned] |
| PB6 | Report draft | After containment | Post a structured comment pre-filled for Summary and Actions Taken | [planned] |
| PB7 | Notify-router | Incident created (labelled P1–P4) | Send the notification for that priority, write the due time as a comment, re-check at the due time | [planned] |

Automation rules (Sentinel, not Logic Apps) and the R6 alert rule are documented in `docs/` once built.
