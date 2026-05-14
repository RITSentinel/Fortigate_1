# FortiGate Diagnostic Runner

Read-only FortiGate troubleshooting and evidence gathering utility for MSP/network engineering teams.

## What it collects

The runner uses SSH to collect practical incident-response evidence:

- System version, uptime, CPU, memory, session statistics, and HA status
- Interface, NIC, ARP, DNS, static route, policy route, and routing-table output
- SD-WAN configuration and health-check output when available
- IPsec tunnel summaries, IKE gateways, tunnel details, and phase 1/phase 2 configuration
- Firewall policy, address object, address group, service, central SNAT, IP pool, and VIP configuration
- Logging configuration

The script writes one text file per command, plus:

- `MASTER_LOG.txt` with all command output in one file
- `SUMMARY.txt` with automatic findings and a technician review checklist

## Safety

- Runs read-only `get`, `show`, and `diagnose ... list/status/stat` commands only.
- Does not change firewall configuration; it uses a large SSH terminal size and advances pagination prompts if `--More--` appears.
- Does not run packet captures, debug flow, tunnel resets, or configuration changes.
- Redacts common secret fields such as passwords, PSKs, secrets, private keys, and tokens from saved output.

## Requirements

- Python 3.9+
- Paramiko

Install Paramiko if needed:

```bash
python3 -m pip install paramiko
```

## Usage

```bash
./fortigate_diag_runner --host x.x.x.x --user admin --name Client-Site
```

Common options:

```bash
./fortigate_diag_runner --host x.x.x.x --user admin --name Client-Site --command-timeout 60
./fortigate_diag_runner --host x.x.x.x --user admin --name Client-Site --extended
./fortigate_diag_runner --host x.x.x.x --user admin --name Client-Site --strict-host-key
```

Options:

- `--host`: FortiGate IP address or hostname.
- `--user`: SSH username.
- `--port`: SSH port, default `22`.
- `--name`: Friendly client/site name used in the output folder name.
- `--out`: Base output folder, default `fortigate_diagnostics`.
- `--command-timeout`: Seconds to wait for each command before saving partial output, default `30`.
- `--extended`: Also collect optional IPv6, VDOM, and zone context.
- `--strict-host-key`: Reject unknown SSH host keys instead of auto-accepting them.

## Operational notes

- Use a read-only or least-privilege admin account where possible.
- If a command returns a FortiGate CLI error, the output is still saved. This can happen when a command is unavailable on a FortiOS version, feature set, or VDOM scope.
- During VPN incidents, record the exact source IP, destination IP, destination port, failed-test time, and timezone alongside the generated folder.
- A tunnel being established does not prove traffic is passing. Review routes, selectors, firewall policies in both directions, NAT, and whether TX/RX or encrypted/decrypted counters move during a live test.
