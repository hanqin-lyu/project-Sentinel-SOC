# [PBn: playbook name]

| Item | Value |
|---|---|
| Purpose | [one sentence; one job only] |
| Trigger | [incident / schedule / called by PBx] |
| Inputs | [incident fields or parameters used] |
| Outputs | [comments, tags, resource changes] |
| Owner | [name] |

## Parameters

| Name | Default | Meaning |
|---|---|---|
| [KillSwitch] | [true/false] | [when false, notify only] |
| [other] | | |

## Identity and roles

| Identity | Role | Scope | Why |
|---|---|---|---|
| [managed identity] | [role] | [scope] | [action that needs it] |

## Steps

1. [step]
2. [step]

## Guards and failure handling

- [guards: private ranges, Trusted_IPs, already blocked, kill switch]
- [retry policy, timeout, call to the failure handler]

## Test cases

| Case | Expected result | Run on | Result |
|---|---|---|---|
| [case] | [expected] | [date] | [pass / fail, run ID] |

## Deployment

[az deployment group create ... --parameters @azuredeploy.parameters.local.json]
