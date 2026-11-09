# Both providers sign in with GitHub OIDC. Subscription, tenant and client IDs
# come from the ARM_* environment variables set by the workflow, so no ID is
# written in this repo.
provider "azurerm" {
  features {}
  use_oidc = true
}

provider "azapi" {
  use_oidc = true
}
