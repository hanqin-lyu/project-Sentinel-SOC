# Teardown

Remove the billable resources to stop spend, and keep everything reusable.
Run this only after the evidence for the current run is captured.

## Before you destroy

- Evidence is saved in `docs/evidence/` (redacted) and `docs/evidence/raw/`
  (local only). Capture anything else you still need first.
- **Destroying the Log Analytics workspace erases its history for good** —
  Syslog, incidents and `SOARBlocks_CL` all go. That is expected here; the
  evidence is already saved.

## What goes, what stays

Removed (the billable parts):

- Honeypot VM, its OS disk, NIC and public IP
- Log Analytics workspace + Microsoft Sentinel, and the syslog DCR
- Logic Apps playbooks, their API connections and the automation rules
- The playbook identities' role assignments

Kept:

- The three resource groups — they are `data` sources in the code, not
  `resource`, so `terraform destroy` never touches them. Reuse them next time.
- The Terraform state storage account and container — made by hand, outside
  Terraform.
- The `governance/` policy exemption — separate state, applied by hand. It has
  no effect once the honeypot NSG is gone; remove it by hand later if you want.
- All repo code.

## Option 1 — destroy through the pipeline (recommended)

Same CD identity, same backend and the same `production-demo` approval gate as
apply. No Azure login or secrets on your laptop.

1. In `.github/workflows/terraform.yml`, give `workflow_dispatch` a mode input:

   ```yaml
     workflow_dispatch:
       inputs:
         mode:
           description: "apply or destroy"
           type: choice
           options: [apply, destroy]
           default: apply
   ```

2. Stop the apply job from running on a destroy dispatch — change its `if:`
   (the `terraform-apply` job) to:

   ```yaml
       if: >-
         github.event_name != 'pull_request' &&
         !(github.event_name == 'workflow_dispatch' && inputs.mode == 'destroy')
   ```

3. Add a destroy job (the top-level `env:` already exports `BACKEND_CONFIG` and
   the `TF_VAR_*` inputs, so this stays short):

   ```yaml
     terraform-destroy:
       name: "Terraform Destroy"
       if: github.event_name == 'workflow_dispatch' && inputs.mode == 'destroy'
       runs-on: ubuntu-latest
       environment: production-demo
       concurrency:
         group: terraform
         cancel-in-progress: false
       env:
         ARM_CLIENT_ID: ${{ secrets.AZURE_CD_CLIENT_ID }}
         ARM_TENANT_ID: ${{ secrets.AZURE_CD_TENANT_ID }}
       steps:
         - uses: actions/checkout@v4
         - uses: hashicorp/setup-terraform@v3
           with:
             terraform_version: "1.15.8"
             terraform_wrapper: false
         - name: Terraform init
           run: terraform init -input=false $BACKEND_CONFIG
         - name: Terraform destroy
           run: terraform destroy -input=false -no-color -auto-approve
   ```

4. Merge that change, then run it: Actions tab -> Terraform -> Run workflow ->
   `mode = destroy` -> approve the `production-demo` deployment.

## Option 2 — destroy locally (alternative)

Uses your own `az login` instead of the pipeline. Needs the backend values and
two Terraform inputs (all GitHub repo variables), plus a small local override so
the providers use CLI auth instead of OIDC.

```bash
az login

# gitignored local override: providers authenticate with your az login, not OIDC
cat > override.tf <<'EOF'
provider "azurerm" { use_oidc = false }
provider "azapi"   { use_oidc = false }
EOF

terraform init -reconfigure \
  -backend-config="use_oidc=false" \
  -backend-config="resource_group_name=<TFSTATE_RESOURCE_GROUP>" \
  -backend-config="storage_account_name=<TFSTATE_STORAGE_ACCOUNT>" \
  -backend-config="container_name=<TFSTATE_CONTAINER>"

export ARM_SUBSCRIPTION_ID="<subscription id>"
export TF_VAR_admin_ssh_public_key="<ADMIN_SSH_PUBLIC_KEY value>"
export TF_VAR_sentinel_automation_principal_id="<SENTINEL_AUTOMATION_PRINCIPAL_ID value>"

terraform plan -destroy        # review first
terraform destroy

rm override.tf                 # drop the local override when done
```

Your `az login` account needs Storage Blob Data Contributor on the state
container and delete rights in the three resource groups; as subscription owner
you have both. Do not commit `override.tf`, and do not paste the subscription ID
or principal ID into any tracked file.

## After destroy

Check each group is empty (the groups themselves stay):

```bash
az resource list -g rg-soc-sentinel    -o table
az resource list -g rg-lab-honeypot    -o table
az resource list -g rg-core-automation -o table
```

To rebuild later, run the apply pipeline again (open a PR, merge, approve
`production-demo`); it recreates everything from this code.
