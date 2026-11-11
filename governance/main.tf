# The subscription-wide deny policy from project-IaC-Azconfig blocks NSG rules
# that open SSH to the Internet. The honeypot opens port 22 on purpose, so its
# resource group alone is exempt. Every other resource group stays protected.
data "azurerm_subscription" "current" {}

data "azurerm_resource_group" "honeypot" {
  name = "rg-lab-honeypot"
}

resource "azurerm_resource_group_policy_exemption" "honeypot_open_ssh" {
  name                 = "exempt-honeypot-open-ssh"
  display_name         = "Honeypot by design: open SSH"
  description          = "SSH 22 is intentionally open to the Internet. Isolated resource group; the VM identity has no roles."
  resource_group_id    = data.azurerm_resource_group.honeypot.id
  policy_assignment_id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Authorization/policyAssignments/audit-nsg-open-ssh-assignment"
  exemption_category   = "Waiver"
}
