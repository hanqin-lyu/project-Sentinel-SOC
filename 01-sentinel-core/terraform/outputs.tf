output "workspace_id" {
  description = "Resource ID of the Log Analytics workspace with Sentinel."
  value       = module.workspace.resource_id
}

output "dcr_id" {
  description = "Resource ID of the honeypot syslog DCR. Stack 02 looks it up by name."
  value       = module.dcr_honeypot_syslog.resource_id
}
