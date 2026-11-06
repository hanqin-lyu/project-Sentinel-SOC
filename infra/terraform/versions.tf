terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}

  # azurerm 4.x requires the subscription ID. It comes from a variable (terraform.tfvars is
  # git-ignored) so it never lands in version control.
  subscription_id = var.subscription_id
}
