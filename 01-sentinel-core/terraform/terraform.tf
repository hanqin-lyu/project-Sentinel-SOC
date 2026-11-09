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
    key              = "sentinel.tfstate"
    use_oidc         = true
    use_azuread_auth = true
  }
}
