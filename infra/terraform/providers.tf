provider "azurerm" {
  features {}

  # azurerm 4.x requires the subscription ID. It comes from a variable (terraform.tfvars is
  # git-ignored) so it never lands in version control.
  subscription_id = var.subscription_id
}
