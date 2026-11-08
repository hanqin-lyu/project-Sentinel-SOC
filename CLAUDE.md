# Project: Closed-Loop SOC Automation on Microsoft Sentinel

A solo portfolio project. An Azure SSH honeypot feeds Microsoft Sentinel (used in the Defender portal); custom KQL rules raise incidents; Logic Apps playbooks respond. The owner reads every change as a diff in VS Code and commits it himself.

## Hard rules (do not break, even if asked in passing)

1. **Never commit, push, stage, reset, clean or rebase.** Edit files only. The owner reviews the diff and commits.
2. **Never run `terraform apply`, `destroy`, `import` or `state`.** The owner runs these. Allowed: `terraform fmt`, `terraform init -backend=false`, `terraform validate`. Do not run `terraform plan`; ask the owner to run it and paste the output.
3. **No Azure changes.** Do not run `az login`, and do not run any `az` command that creates, updates or deletes anything. Read-only `az ... show/list` is fine only if the owner is already logged in.
4. **No secrets.** Do not read or write `terraform.tfvars`, `*.tfstate`, `.env`, keys or `*.parameters.local.json`. Only `terraform.tfvars.example` with placeholders is allowed. Never put a subscription ID, tenant ID, key or real attacker IP in a file.
5. **Never invent results.** Metrics, incident data, timestamps and screenshots come from real runs. Until then use `[placeholders]`.
6. **The honeypot must stay isolated.** The VM identity has no role assignments, and port 22 is the only intentionally open inbound port.

## Keep it simple

- No variables, options or files "for later". If a value is not set by the owner, hard-code it.
- Terraform file names: `terraform.tf`, `providers.tf`, `variables.tf`, `outputs.tf`, `main.<topic>.tf`.
- One job per playbook. Steps that need no external call go in a Sentinel automation rule (see `playbooks/README.md`).
- Out of scope: AI/ML analysis, threat hunting, multi-workspace or multi-cloud collection. They belong to a separate project.

## Layout

- `infra/terraform/`: honeypot network and VM, workspace, Sentinel (not yet validated or applied)
- `playbooks/`: Logic Apps playbooks and index (nothing built yet)
- `docs/`: phase 0 checklist, SLA (P1–P4), triage reports (drafts with placeholders)

## Writing

- Repo files are in English, short and plain. The owner writes to you in Chinese; reply in Chinese.
- Triage reports: UTC with AEDT alongside, IPs and URLs defanged (`203[.]0[.]113[.]10`, `hxxp://`).
- The Word plan (`SIEM_Honeypot_SOC_Closed_Loop.docx`) is the source of truth for scope and schedule. If a file here disagrees with it, ask.
