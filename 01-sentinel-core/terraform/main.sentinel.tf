# Turns Sentinel on for the workspace. This starts the 31-day free trial, so
# merge the PR that first applies this on build day.
# No AVM module covers Sentinel onboarding, so this is the native resource.
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "soc" {
  workspace_id = module.workspace.resource_id
}
