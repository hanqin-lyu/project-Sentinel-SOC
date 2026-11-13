# Evidence

Redacted screenshots of the lab running. The account name, tenant, the owner's
management IP and real attacker IPs are blacked out (CLAUDE.md rule 4). The raw
originals stay in `raw/`, which is gitignored and never committed.

| File | Shows |
|---|---|
| `pb6-soarblocks-block-unblock.png` | `SOARBlocks_CL`: PB5 wrote `Block` rows, and PB6 wrote matching `Unblock` rows when each block's TTL expired. |
| `pb6-nsg-rule-reverted.png` | `nsg-honeypot`: after PB6 ran, `SOAR-Block-Attackers` is back to its placeholder source (`192.0.2.1`); no live attacker IP remains in the deny rule. |
| `pb6-advanced-hunting-unblock.png` | Defender advanced hunting: the PB6 `Unblock` row for the expired test block. |

To publish another shot, copy it from `raw/`, black out the account area
(top-right), any management IP and any real attacker IP, then save it here.
`192.0.2.1`, `203.0.113.0/24` and similar are documentation ranges and are safe
to keep.
