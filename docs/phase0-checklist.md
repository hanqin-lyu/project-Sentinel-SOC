# Phase 0: guardrails and foundation

Exit criteria: budget alert in place, three resource groups, workspace with a daily cap, Sentinel enabled, Defender portal access confirmed, repository conventions in place.

## Order of work

1. **Budget first, before anything that costs money.** Azure portal, Cost Management, Budgets, create a budget at the subscription scope (or filter to the three `RG-SOC-*` groups). Choose a monthly amount you can accept losing. Add actual-cost alerts at 50%, 80% and 100% to your email, plus a forecast alert if offered. A budget only notifies, it does not stop spending, and emails normally arrive within about an hour of evaluation. Amount chosen: [fill in].
2. **Resource groups and workspace:** `./infra/phase0.sh` (asks for confirmation on the active subscription). Region defaults to `australiaeast`; override with `LOCATION=...`. Check the Sentinel and Log Analytics pricing page for your region before settling.
3. **Enable Sentinel, on build day:** `ENABLE_SENTINEL=yes ./infra/phase0.sh`. This starts the 31-day free trial (first 10 GB/day, limited to 20 workspaces per tenant), so run it when you are ready to start the honeypot, not earlier. If the CLI extension syntax has changed, run `az sentinel onboarding-state create --help`, or enable Sentinel in the portal: Microsoft Sentinel, Create, select the workspace, Add.
4. **Defender portal access.** Open https://security.microsoft.com and confirm Microsoft Sentinel appears. A new Sentinel customer with Owner or User Access Administrator on the subscription is onboarded to the Defender portal automatically. If the workspace does not appear: Settings, Microsoft Sentinel, SIEM workspaces, select the workspace, Connect workspace, set as Primary. A missing role is the usual cause when the workspace or subscription is blank.
5. **Record what you did** in the table below, with a redacted screenshot under `docs/evidence/`.

## Record

| Item | Value |
|---|---|
| Subscription (name only) | [fill in] |
| Region | [fill in] |
| Budget amount and alert thresholds | [fill in] |
| Workspace name, daily cap, retention | [fill in] |
| Sentinel enabled on (date, UTC) | [fill in] |
| Free trial ends (31 days later) | [fill in] |
| Defender portal access confirmed | [yes / no, how] |

## Verification

```bash
az group list --query "[?starts_with(name,'RG-SOC')].{name:name,location:location}" -o table
az monitor log-analytics workspace show -g RG-SOC-Sentinel -n law-soc-sentinel \
  --query "{cap:workspaceCapping.dailyQuotaGb, retention:retentionInDays, sku:sku.name}" -o table
```

## Notes

- The daily cap is a backstop, not cost control: when it is reached, collection stops for the rest of the day and some overshoot is still billed. In Phase 1, add an alert for the cap being reached (an event is written to the `Operations` table) and one at about 70% of the cap. Filtering belongs in rsyslog, auditd and the DCR transformation.
- Do not put subscription IDs, tenant IDs or tokens in committed files. Screenshots must be redacted.
