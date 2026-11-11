# Phase 0: foundation (day 1)

Done when: budget alerts set, the Terraform is applied through the pipeline, Defender portal shows Sentinel, syslog rows arrive, and the checks at the end pass.

## 1. One-time setup (by hand)

1. **Budget** (portal, already created): add Actual 80% and 100% alerts and narrow the scope to the subscription or the three resource groups. A budget only sends emails, it does not stop spending.
2. **State storage:** create a storage account and a blob container for Terraform state (outside the three resource groups). Give both pipeline identities **Storage Blob Data Contributor** on the container.
3. **OIDC:** the CI and CD identities from project-IaC-Azconfig are reused. Federated credentials are per repository, so add new ones for this repo. GitHub sends this repo's subject with the owner and repo IDs (`repo:<owner>@<owner-id>/project-Sentinel-SOC@<repo-id>:...`), so the portal's GitHub template does not match. Use the explicit subject form (Entity type "Other issuer" or "Explicit subject identifier") and copy the prefix from the first `AADSTS700213` error:
   - CI identity: `<prefix>:pull_request` (CI on the PR)
   - CD identity: `<prefix>:environment:production-demo` (CD, after the review)
   - Issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`.
4. **Resource groups** (already created): `rg-soc-sentinel`, `rg-lab-honeypot` and `rg-core-automation`. They can be reused by other projects. Terraform only looks them up.
5. **Resource providers:** register these on the subscription, because the pipeline cannot: `Microsoft.OperationalInsights`, `Microsoft.OperationsManagement`, `Microsoft.SecurityInsights`, `Microsoft.Insights`, `Microsoft.Network`, `Microsoft.Compute`, `Microsoft.Logic`, `Microsoft.Web`.
6. **Roles:**
   - CI identity: Reader on the subscription.
   - CD identity, on each of the three resource groups and nothing on the subscription: Contributor, and Role Based Access Control Administrator with the condition "Allow user to assign all roles except privileged administrator roles Owner, UAA, RBAC".
7. **Azure Policy:** the exemption from the open-SSH deny policy is Terraform in `governance/`. Apply it by hand after `az login`, before approving the first deployment. The CD identity needs no policy permissions.
8. **GitHub settings** for this repo:
   - Environment `production-demo`: add yourself under **Required reviewers**, leave "Prevent self-review" off (you are the only reviewer), and limit **Deployment branches** to `main`. The CD identity's credential only works inside this environment, so nothing can apply without your approval.
   - Environment secrets in `production-demo`: `AZURE_CD_CLIENT_ID`, `AZURE_CD_TENANT_ID`. Only the CD apply job runs in this environment, so only it can read them, and only after your approval. Do not keep a repository secret with the same name.
   - Repository secrets: `AZURE_SUBSCRIPTION_ID`, `AZURE_CI_CLIENT_ID`, `AZURE_CI_TENANT_ID`, `MANAGEMENT_SOURCE_CIDR` (your IP as /32). The CI identity is used by the pull request jobs, which run outside the environment.
   - Variables: `TFSTATE_RESOURCE_GROUP`, `TFSTATE_STORAGE_ACCOUNT`, `TFSTATE_CONTAINER`, `ADMIN_SSH_PUBLIC_KEY`.
   - Branch protection on `main`: require a pull request (no required approvals, you are the only reviewer) and the status check `Terraform Plan Preview`. The check can be selected only after CI has run once.

## 2. Deploy (one PR)

1. Open one PR with all the Terraform. The first Checkov run will list honeypot-by-design findings; add inline skips with that reason, then push again.
2. Read the plan in the job summary, then merge. The merge starts the apply job, which waits; approve it under Review deployments. This turns Sentinel on, starts the 31-day free trial and exposes the honeypot to the Internet, so do it on build day.

## 3. On the VM (by hand, over SSH as `azureops` on port 22)

1. Create the weak-password decoy account, and allow password login for that account only (Terraform turns password login off in sshd).
2. Add an sshd listener on port 2222 for admin access. Ubuntu 24.04 starts sshd through a socket, so add the port in an `ssh.socket` override. Check with `ss -tlnp`.
3. Check that rows arrive in the `Syslog` table, including `local6` (auditd).
4. Change `lockdown_egress` to `true` in `honeypot.tf` in a PR, to block outbound Internet.

## 4. Checks before building

- **Defender portal:** open https://security.microsoft.com and confirm Sentinel appears. If not, check you are Owner or User Access Administrator on the subscription.
- A Logic App can post a Teams message.
- A Logic App identity can edit one NSG rule and run a harmless command on the VM. Write down which roles it needed.
- After the playbooks are applied, check each playbook identity has only the roles in `README.md` (Identities). Write down any extra role a playbook needed.

## Record

| Item | Value |
|---|---|
| Region | australiaeast |
| Budget | SOC-Lab-Budget, USD 20/month. TODO: Actual 80% and 100% alerts, narrower scope |
| Sentinel enabled on (UTC) | 2026-11-11 03:42 |
| Free trial ends (+31 days) | 2026-12-12 |
| Defender portal access | [yes / no] |
| Policy exemption on rg-lab-honeypot | needed, applied (`exempt-honeypot-open-ssh`, Waiver, no expiry) |
