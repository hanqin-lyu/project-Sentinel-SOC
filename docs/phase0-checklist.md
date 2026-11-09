# Phase 0: foundation (day 1)

Done when: budget alerts set, all three stacks are applied through the pipeline, Defender portal shows Sentinel, syslog rows arrive, and the checks at the end pass.

## 1. One-time setup (by hand)

1. **Budget** (portal, already created): add Actual 80% and 100% alerts and narrow the scope to the subscription or the `RG-SOC-*` groups. A budget only sends emails, it does not stop spending.
2. **State storage:** create a storage account and a blob container for Terraform state (outside the `RG-SOC-*` groups). Give both pipeline identities **Storage Blob Data Contributor** on the container.
3. **OIDC:** the CI and CD identities from project-IaC-Azconfig are reused. Federated credentials are per repository, so add new ones for this repo. GitHub sends this repo's subject with the owner and repo IDs (`repo:<owner>@<owner-id>/project-Sentinel-SOC@<repo-id>:...`), so the portal's GitHub template does not match. Use the explicit subject form (Entity type "Other issuer" or "Explicit subject identifier") and copy the prefix from the first `AADSTS700213` error:
   - CI identity: `<prefix>:pull_request` (CI on the PR)
   - CD identity: `<prefix>:environment:production-demo` (CD, after the review)
   - Issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`.
4. **Roles:**
   - CI identity: Reader on the subscription.
   - CD identity: Contributor on the subscription (it creates the resource groups) and Microsoft Sentinel Contributor.
   - Later, for the playbook identities (Module 4), the CD identity also needs RBAC Administrator, with a condition that limits it to the roles in the plan.
5. **Azure Policy:** if the deny policy from project-IaC-Azconfig blocks SSH open to the Internet, add a policy exemption on `RG-SOC-Honeypot` with the reason "honeypot by design".
6. **GitHub settings** for this repo:
   - Environment `production-demo`: add yourself under **Required reviewers**, leave "Prevent self-review" off (you are the only reviewer), and limit **Deployment branches** to `main`. The CD identity's credential only works inside this environment, so nothing can apply without your approval.
   - Environment secrets in `production-demo`: `AZURE_CD_CLIENT_ID`, `AZURE_CD_TENANT_ID`. Only the CD apply job runs in this environment, so only it can read them, and only after your approval. Do not keep a repository secret with the same name.
   - Repository secrets: `AZURE_SUBSCRIPTION_ID`, `AZURE_CI_CLIENT_ID`, `AZURE_CI_TENANT_ID`, `MANAGEMENT_SOURCE_CIDR` (your IP as /32). The CI identity is used by `terraform-ci.yml`, which runs outside the environment.
   - Variables: `TFSTATE_RESOURCE_GROUP`, `TFSTATE_STORAGE_ACCOUNT`, `TFSTATE_CONTAINER`, `ADMIN_SSH_PUBLIC_KEY`.

## 2. Deploy (one PR per stack, in order)

1. **01 Sentinel core:** open the PR, read the plan in the job summary, merge. The merge starts Terraform CD, which waits; approve it under Review deployments. This turns Sentinel on and starts the 31-day free trial, so do it on build day.
2. **02 Honeypot:** same steps. The first Checkov run will list honeypot-by-design findings; add inline skips with that reason, then rerun.
3. **03 Automation:** same steps.

## 3. On the VM (by hand, over SSH as `azureops` on port 22)

1. Create the weak-password decoy account, and allow password login for that account only (Terraform turns password login off in sshd).
2. Add an sshd listener on port 2222 for admin access. Ubuntu 24.04 starts sshd through a socket, so add the port in an `ssh.socket` override. Check with `ss -tlnp`.
3. Check that rows arrive in the `Syslog` table, including `local6` (auditd).
4. Change `lockdown_egress` to `true` in `02-infrastructure-honeypot/main.resource_group.tf` in a PR, to block outbound Internet.

## 4. Checks before building

- **Defender portal:** open https://security.microsoft.com and confirm Sentinel appears. If not, check you are Owner or User Access Administrator on the subscription.
- A Logic App can post a Teams Approve/Deny card.
- A Logic App identity can edit one NSG rule and run a harmless command on the VM. Write down which roles it needed.

## Record

| Item | Value |
|---|---|
| Region | australiaeast |
| Budget | SOC-Lab-Budget, USD 20/month. TODO: Actual 80% and 100% alerts, narrower scope |
| Sentinel enabled on (UTC) | [fill in] |
| Free trial ends (+31 days) | [fill in] |
| Defender portal access | [yes / no] |
| Policy exemption on RG-SOC-Honeypot | [needed / not needed] |
