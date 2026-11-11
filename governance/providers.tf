# Governance and control plane. Applied by hand by the owner after az login,
# as with 01-platform-policy in project-IaC-Azconfig. The pipeline never
# applies this folder, so the CD identity needs no policy permissions.
terraform {
  required_version = ">= 1.11, < 2.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  # Own state, separate from the pipeline's. The storage account, resource
  # group and container are passed with -backend-config.
  backend "azurerm" {
    key              = "governance.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
}
