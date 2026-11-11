# Logic Apps playbooks and their API connections go in this resource group.
# Sentinel's service account gets Microsoft Sentinel Automation Contributor
# here only, so automation rules can run the playbooks and nothing else.
# Playbooks are added when Phase 3 starts.
# Created by hand, so the pipeline needs no subscription-level write access.
data "azurerm_resource_group" "automation" {
  name = "rg-core-automation"
}
