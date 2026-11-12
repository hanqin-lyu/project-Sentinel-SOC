# Attack simulation: end-to-end validation

How to drive a real SSH brute force against the honeypot and watch the closed loop
run: detections R1/R2/R4/R5 raise incidents, automation rule `AR-R2` runs PB5
to block the attacker, and the notifiers PB2/PB3/PB4 tag each incident and post
it to Slack. Run it from a network **outside** `MANAGEMENT_SOURCE_CIDR`, so you
never block or trust yourself.

Validated end to end on 2026-11-12: R1 alerts, R5/R2/R4 incidents, and the PB5
block (NSG rule + `SOARBlocks_CL` row + incident comment) all fired on real
telemetry. Placeholders below stand in for the honeypot and attacker addresses;
never write a real IP in the repo.

## What you need

- A source network **different from `MANAGEMENT_SOURCE_CIDR`** (a phone hotspot
  works). Confirm it: `curl -4 -s ifconfig.me` must not equal your management IP.
- `hydra` installed locally.
- The honeypot public IP, `[HONEYPOT_IP]`.
- The Slack webhook secret `slack-webhook-url` set in the playbook Key Vault, and
  the `#soc-alerts` channel open, so PB2/PB3/PB4 can post (see README design
  notes). Without the secret the notifiers fail at the Key Vault read.
- Three wordlists, kept **outside the repo** (the decoy password must never be
  committed):
  - the decoy username only;
  - `wrong-pw.txt` — 50 or more wrong passwords, **none equal to the decoy
    password** (for R5, which must see only failures);
  - `with-success.txt` — about 20 wrong passwords, then the decoy password as the
    **last** line (for R2, so one hydra run makes the failures and the successful
    login from the same source IP).

## Gotchas that make or break the run

1. **IPv4 only.** The honeypot public IP is IPv4. Connect over IPv4: use `curl -4`
   and let hydra/ssh use the IPv4 address. `ifconfig.me` may answer with an IPv6
   address, which is not what the honeypot sees.
2. **Ingestion delay.** Each rule counts its "last 10 minutes" by `ingestion_time()`
   (see README design notes), so a short burst that reaches the workspace a minute
   or two late is still caught. Expect an incident 10-20 minutes after the attack,
   not instantly.
3. **R5 before any success.** R5 excludes an IP that has any successful login in
   the last 24 hours. Do the R5 step (failures only) **before** you log in from
   that source.
4. **Mobile NAT rotates the IP.** Carrier-grade NAT on a hotspot can hand out a
   different public IP for each connection. R2 correlates the brute force and the
   login by the **same** IP, so a separate hydra run and a separate `ssh` often
   land on different IPs and R2 never fires. Use `with-success.txt` so one hydra
   run makes both the failures and the success from one IP, and confirm with the
   SourceIP summary query before you expect R2.

## Steps

0. **Pre-checks** (from the attacking host):
   - `curl -4 -s ifconfig.me` — note it, and confirm it differs from the
     management IP.
   - `nc -vz -4 [HONEYPOT_IP] 22` — must succeed.

1. **R5 + R1 (brute force, no login).**
   `hydra -l [DECOY_USER] -P wrong-pw.txt -t 4 -I ssh://[HONEYPOT_IP]`
   50 or more failures in under 10 minutes, ending `0 valid password found`. Wait
   about 15 minutes, then expect an **R5 Sustained brute force** (Low) incident and
   **R1 SSH brute force** alerts (R1 is alert only).

2. **R2 + R4 + PB5 (compromise then probe).**
   - `hydra -l [DECOY_USER] -P with-success.txt -t 4 -I ssh://[HONEYPOT_IP]` — ends
     `1 valid password found`: one run, one source IP, about 20 failures and one
     success.
   - `ssh [DECOY_USER]@[HONEYPOT_IP]`, then on the VM run `sudo id` (the decoy is
     not in sudoers) to raise **R4 Sudo probing** (Medium).
   - Wait about 15 minutes. Expect an **R2 Compromise after brute force** (High)
     incident; `AR-R2` runs PB5 automatically.

3. **Check PB5.**
   - The R2 incident has a PB5 comment with the defanged IP and a 24-hour expiry.
   - `nsg-honeypot` rule `SOAR-Block-Attackers` now denies the attacker IP.
   - `SOARBlocks_CL` has a `Block` row with `ExpiresAt` 24 hours out.

4. **Check PB6 (next day).** After the TTL, PB6 (hourly) removes the IP from the
   rule, writes an `Unblock` row to `SOARBlocks_CL`, and comments on the incident.

5. **Check the notifiers (PB2/PB3/PB4).** Each incident above also runs its
   notifier: R5 runs PB3 (P3), R4 runs PB2 (P2), R2 runs PB4 (P1).
   - **Slack.** `#soc-alerts` has one message per incident, with the severity,
     incident number and title, the defanged source IP, and the created time.
     The P2 and P3 messages link the SLA doc; the P1 message says PB5 is blocking.
   - **Tag.** Each incident carries the matching label (`P1`/`P2`/`P3`). Confirm
     the label was **added**, not that it replaced an existing one.
   - **Comment.** PB2 comments the acknowledge-by time (30 min from creation);
     PB3 comments the daily-review target.
   - **No secret leak.** Open the playbook run (Logic App run history): the
     `Get_webhook` output and the `Send_slack` input show as secured, so the
     webhook URL is not visible.

## Queries

**Did the failures and the success share one IP? (run before expecting R2)**

```kql
Syslog
| where TimeGenerated > ago(20m)
| where Facility in ("auth","authpriv") and ProcessName in ("sshd","sshd-session")
| extend SourceIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
| summarize Failures = countif(SyslogMessage has_any ("Failed password","Invalid user","Connection closed by authenticating user")),
            Success  = countif(SyslogMessage startswith "Accepted ")
    by SourceIP
| order by Failures desc
```

One row with `Failures >= 10` and `Success >= 1` means R2 will fire for that IP.

**Incidents**

```kql
SecurityIncident
| where TimeGenerated > ago(1h)
| project TimeGenerated, Title, Severity, Status, IncidentNumber
| order by TimeGenerated desc
```

**Blocks**

```kql
SOARBlocks_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, IPAddress, Action, ExpiresAt, Playbook
| order by TimeGenerated desc
```

## Record

| Item | Value |
|---|---|
| Last validated (UTC) | 2026-11-12 |
| Rules fired | R1 (alert only), R5, R2, R4 |
| PB5 | Blocked `[ATTACKER_IP]`: NSG rule + `SOARBlocks_CL` Block row + incident comment, TTL 24 h |
| PB6 | [to verify after the TTL] |
| PB2/PB3/PB4 | [to verify: tag added, Slack message in `#soc-alerts`, webhook secured in run history] |
