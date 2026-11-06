#!/usr/bin/env bash
# Phase 0: guardrails and foundation.
# Creates the three resource groups and the Log Analytics workspace (with a daily
# ingestion cap). Enabling Microsoft Sentinel is a separate, explicit step because
# it starts the 31-day free trial clock: run with ENABLE_SENTINEL=yes on the day you
# start building the honeypot.
#
# Prerequisites: Azure CLI, `az login`, Contributor on the target subscription.
# Not handled here: the cost budget (create it in the portal, see
# docs/phase0-checklist.md).
set -euo pipefail

LOCATION="${LOCATION:-australiaeast}"
RG_HONEYPOT="${RG_HONEYPOT:-RG-SOC-Honeypot}"
RG_SENTINEL="${RG_SENTINEL:-RG-SOC-Sentinel}"
RG_AUTOMATION="${RG_AUTOMATION:-RG-SOC-Automation}"
WORKSPACE="${WORKSPACE:-law-soc-sentinel}"
DAILY_CAP_GB="${DAILY_CAP_GB:-1}"      # backstop only; revisit after the 48-hour ingestion report
RETENTION_DAYS="${RETENTION_DAYS:-90}" # Sentinel guidance: 90 days
ENABLE_SENTINEL="${ENABLE_SENTINEL:-no}"
TAGS="project=sentinel-soc owner=hanqin-lyu"

echo "Active subscription:"
az account show --query "{name:name, id:id, user:user.name}" -o table
read -r -p "Create resources in this subscription? [y/N] " ans
[[ "${ans:-n}" == "y" ]] || { echo "Aborted."; exit 1; }

for rg in "$RG_HONEYPOT" "$RG_SENTINEL" "$RG_AUTOMATION"; do
  az group create --name "$rg" --location "$LOCATION" --tags $TAGS --output none
  echo "Resource group ready: $rg"
done

az monitor log-analytics workspace create \
  --resource-group "$RG_SENTINEL" \
  --workspace-name "$WORKSPACE" \
  --location "$LOCATION" \
  --sku PerGB2018 \
  --retention-time "$RETENTION_DAYS" \
  --quota "$DAILY_CAP_GB" \
  --tags $TAGS \
  --output none
echo "Workspace ready: $WORKSPACE (daily cap ${DAILY_CAP_GB} GB, retention ${RETENTION_DAYS} days)"

if [[ "$ENABLE_SENTINEL" == "yes" ]]; then
  az extension add --name sentinel --upgrade --only-show-errors
  az sentinel onboarding-state create \
    --resource-group "$RG_SENTINEL" \
    --workspace-name "$WORKSPACE" \
    --name default
  echo "Microsoft Sentinel enabled. The 31-day free trial (first 10 GB/day) starts now."
else
  echo "Sentinel NOT enabled. Re-run with ENABLE_SENTINEL=yes when you start the honeypot build."
fi

echo "Next: set the budget and check Defender portal access (docs/phase0-checklist.md)."
