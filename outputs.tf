output "workspace_id" {
  description = "Resource ID of the Log Analytics workspace with Sentinel."
  value       = module.workspace.resource_id
}

output "honeypot_public_ip" {
  description = "Public IP of the honeypot. Attackers and attacker-sim connect here."
  value       = module.pip.public_ip_address
}

output "nsg_name" {
  description = "The NSG whose SOAR-Block-Attackers rule the playbook edits."
  value       = module.nsg.name
}

output "vm_id" {
  description = "Resource ID of the honeypot VM (target of the Run Command step)."
  value       = module.vm.resource_id
}
