# Terraform, provider and backend settings. Commit .terraform.lock.hcl so CI
# uses the same provider builds.
terraform {
  # 1.11 is the minimum for the AVM modules used in this repo.
  required_version = ">= 1.11, < 2.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # The AVM modules are built on azapi.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.12"
    }
  }

  # State lives in a storage account the owner created by hand. The workflow
  # passes the account, resource group and container with -backend-config.
  # Local checks use `terraform init -backend=false`.
  backend "azurerm" {
    key              = "soc.tfstate"
    use_oidc         = true
    use_azuread_auth = true
  }
}

# Both providers sign in with GitHub OIDC. Subscription, tenant and client IDs
# come from the ARM_* environment variables set by the workflow, so no ID is
# written in this repo.
# The pipeline has no subscription-level rights, so resource providers are
# registered by hand (see docs/phase0-checklist.md).
provider "azurerm" {
  features {}
  use_oidc                        = true
  resource_provider_registrations = "none"
}

provider "azapi" {
  use_oidc                   = true
  skip_provider_registration = true
}
