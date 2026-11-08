output "honeypot_public_ip" {
  description = "Public IP of the honeypot. Attackers and attacker-sim connect here."
  value       = azurerm_public_ip.honeypot.ip_address
}

output "nsg_name" {
  description = "The NSG whose SOAR-Block-Attackers rule the playbook edits."
  value       = azurerm_network_security_group.honeypot.name
}

output "workspace_id" {
  description = "Resource ID of the Log Analytics workspace with Sentinel."
  value       = azurerm_log_analytics_workspace.soc.id
}
