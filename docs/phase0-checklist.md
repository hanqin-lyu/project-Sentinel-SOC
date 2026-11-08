# Phase 0: foundation (day 1)

Done when: budget alerts set, Terraform applied, Defender portal shows Sentinel, and the two checks below pass.

1. **Budget** (portal, already created): add Actual 80% and 100% alerts and narrow the scope to the subscription or the `RG-SOC-*` groups. A budget only sends emails, it does not stop spending.
2. **Terraform** (`infra/terraform/`, see its README): `terraform init`, `validate`, `plan`, read the plan, then `apply`.
3. **Sentinel** is turned on by the same apply, which starts the 31-day free trial. Apply on build day.
   **Log collection:** in the Defender portal, Sentinel, Content hub, install the **Syslog** solution and set up the **Syslog via AMA** connector for the VM (it creates the collection rule and installs the agent). Do this after the decoy account and auditd forwarding are ready (see the Terraform README).
4. **Defender portal:** open https://security.microsoft.com and confirm Sentinel appears. If not, check you are Owner or User Access Administrator on the subscription.
5. **Check before building:**
   - A Logic App can post a Teams Approve/Deny card.
   - A Logic App identity can edit one NSG rule, and run a harmless command on the VM. Write down which roles it needed.

## Record

| Item | Value |
|---|---|
| Region | [fill in] |
| Budget | SOC-Lab-Budget, USD 20/month. TODO: Actual 80% and 100% alerts, narrower scope |
| Sentinel enabled on (UTC) | [fill in] |
| Free trial ends (+31 days) | [fill in] |
| Defender portal access | [yes / no] |
