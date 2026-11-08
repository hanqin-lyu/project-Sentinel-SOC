# Playbooks

Logic Apps playbooks for Microsoft Sentinel, kept as code in this folder. Nothing is built yet.

## Rules

1. **One job per playbook.** A step that needs no external call is a Sentinel automation rule, not a Logic App.
2. **Settings are parameters.** Kill switch, block TTL, approval timeout and score threshold are template parameters, so behaviour changes without copying a playbook.
3. **Each playbook is a folder** with an ARM template (`azuredeploy.json`) and a short `README.md` listing its trigger, the roles its identity needs, and the tests run.
4. **No secrets in files.** Use managed identity, and Key Vault or an API connection for third-party keys.
5. **Templates are a starting point.** If a playbook starts from a Sentinel Content hub template (for example the Teams ones in SOAR Essentials), its README names the template and what was changed.

## Index

| ID | Playbook | Job |
|---|---|---|
| PB1 | Enrichment | Look up the attacker IP and write the result as an incident comment |
| PB2 | Containment decision | Decide: block automatically, auto-close low risk, or leave for review |
| PB3 | Approval | Teams Approve/Deny card for session kill and account lock |
| PB4 | Block expiry | Remove blocks older than the TTL |
| PB5 | Failure handler | Comment on the incident and notify when a playbook fails |
| PB6 | Report draft | Post incident facts as a comment to start the triage report |
| PB7 | Notify-router | Send the notification for the incident's priority (P1–P4) and write the due time as a comment |
