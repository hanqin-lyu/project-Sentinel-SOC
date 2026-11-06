output "resource_group_names" {
  value = {
    honeypot   = azurerm_resource_group.honeypot.name
    sentinel   = azurerm_resource_group.sentinel.name
    automation = azurerm_resource_group.automation.name
  }
}

output "honeypot_public_ip" {
  value = azurerm_public_ip.honeypot.ip_address
}

output "honeypot_vm_principal_id" {
  description = "Managed identity of the VM. It should have zero role assignments."
  value       = azurerm_linux_virtual_machine.honeypot.identity[0].principal_id
}

output "nsg_name" {
  description = "NSG that PB2 edits (rule SOAR-Block-Attackers)."
  value       = azurerm_network_security_group.honeypot.name
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.soc.name
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.soc.id
}

output "dcr_id" {
  value = azurerm_monitor_data_collection_rule.syslog.id
}
