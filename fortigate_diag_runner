#!/usr/bin/env python3
"""
CTS FortiGate Quick Diagnostic Runner

Simple, read-only FortiGate triage collector for MSP firewall/VPN issues.

Purpose:
- Collect common FortiGate evidence quickly.
- Help determine whether an issue is health, WAN, routing, VPN, NAT, or policy related.
- Produce a clean folder with raw output + a simple summary.

Safety:
- Read-only commands only.
- Does not change firewall configuration.
- Does not run debug flow or packet sniffer by default.
- Handles CLI pagination prompts so output does not hang at --More--.

Requirements:
    pip install paramiko

Usage:
    python3 fortigate_diag_runner --host 1.2.3.4 --user admin --name Client-Site

Example:
    python3 fortigate_diag_runner --host 64.1.2.3 --user admin --name RobChiro-Watseka
"""

import argparse
import getpass
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

try:
    import paramiko
except ImportError:
    paramiko = None


CORE_COMMANDS = [
    # System health
    "get system status",
    "get system performance status",
    "diagnose sys session stat",

    # Interfaces / routing / DNS
    "get system interface",
    "diagnose hardware deviceinfo nic",
    "get router info routing-table all",
    "get router info routing-table database",
    "get system arp",
    "show router static",
    "show router policy",
    "show system dns",

    # SD-WAN, if used. These remain harmless if SD-WAN is not configured.
    "show system sdwan",
    "diagnose sys sdwan health-check",

    # VPN status and config
    "get vpn ipsec tunnel summary",
    "diagnose vpn ike gateway list",
    "diagnose vpn tunnel list",
    "show vpn ipsec phase1-interface",
    "show vpn ipsec phase2-interface",

    # Firewall policy / NAT reference
    "show firewall policy",
    "show firewall address",
    "show firewall addrgrp",
    "show firewall service custom",
    "show firewall service group",
    "show firewall central-snat-map",
    "show firewall ippool",
    "show firewall vip",

    # HA, if used
    "get system ha status",

    # Logging reference
    "get log setting",
]

EXTENDED_COMMANDS = [
    # IPv6 is optional in many environments, so keep it out of the default set.
    "show firewall policy6",
    "show router static6",
    "get router info6 routing-table all",

    # Useful context when FortiGate is using zones or virtual domains.
    "show system zone",
    "show system vdom",
]


SENSITIVE_PATTERNS = [
    (re.compile(r"(set\s+psksecret\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(set\s+password\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(set\s+passwd\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(set\s+secret\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(set\s+private-key\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(set\s+token\s+).*", re.IGNORECASE), r"\1<REDACTED>"),
]

PROMPT_RE = re.compile(r"(?:^|\n)[^\r\n]{0,80}[#$]\s*$")
MORE_RE = re.compile(r"(?:--More--|Press any key to continue)", re.IGNORECASE)
CLI_ERROR_RE = re.compile(r"(?:Command fail|Unknown action|Unknown command|parse error|Return code -\d+)", re.IGNORECASE)


@dataclass
class CommandResult:
    command: str
    output: str
    timed_out: bool = False
    cli_error: bool = False


def redact(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "fortigate"


def connect_ssh(host: str, username: str, password: str, port: int, strict_host_key: bool = False):
    if paramiko is None:
        raise RuntimeError("Paramiko is required. Install it with: python3 -m pip install paramiko")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if strict_host_key:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def recv_text(shell) -> str:
    return shell.recv(65535).decode(errors="replace")


def read_shell(shell, timeout: int = 30) -> tuple[str, bool]:
    """Read until the FortiGate prompt returns or timeout expires."""
    output = ""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if shell.recv_ready():
            chunk = recv_text(shell)
            output += chunk
            deadline = time.monotonic() + timeout

            # Pagination should be disabled, but handle it defensively.
            if MORE_RE.search(output):
                shell.send(" ")
                output = MORE_RE.sub("", output)
                continue

            if PROMPT_RE.search(output.rstrip()):
                return output, False
        else:
            time.sleep(0.2)

    return output, True


def drain_shell(shell, settle_seconds: float = 0.5) -> str:
    output = ""
    end = time.monotonic() + settle_seconds
    while time.monotonic() < end:
        if shell.recv_ready():
            output += recv_text(shell)
            end = time.monotonic() + settle_seconds
        else:
            time.sleep(0.1)
    return output


def run_commands(client, commands: Iterable[str], command_timeout: int):
    shell = client.invoke_shell(width=240, height=1000)
    time.sleep(1)
    drain_shell(shell)

    # Keep the session read-only: do not change system console settings.
    # A large PTY height reduces pagination, and read_shell advances any --More-- prompts.
    shell.send("\n")
    read_shell(shell, timeout=5)

    results = []
    for command in commands:
        print(f" > Running: {command}")
        shell.send(command + "\n")
        output, timed_out = read_shell(shell, timeout=command_timeout)
        output = redact(output)
        results.append(CommandResult(command=command, output=output, timed_out=timed_out, cli_error=bool(CLI_ERROR_RE.search(output))))
        if timed_out:
            print(f"   WARNING: timed out after {command_timeout}s; partial output saved", file=sys.stderr)

    shell.close()
    return results


def extract_percent(label: str, text: str):
    # FortiGate output varies, so this is intentionally loose.
    pattern = re.compile(rf"{label}[^\n]*?(\d+)%", re.IGNORECASE)
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def get_result_text(results: Iterable[CommandResult], command: str) -> str:
    for result in results:
        if result.command == command:
            return result.output
    return ""


def analyze(results: Iterable[CommandResult]) -> str:
    results = list(results)
    full_text = "\n".join(result.output for result in results)
    lower = full_text.lower()
    findings = []

    timed_out = [result.command for result in results if result.timed_out]
    cli_errors = [result.command for result in results if result.cli_error]

    if timed_out:
        findings.append(
            "COLLECTION: Some commands hit the timeout and may have partial output: "
            + ", ".join(timed_out)
            + ". Increase --command-timeout if needed."
        )

    if cli_errors:
        findings.append(
            "COLLECTION: Some commands returned FortiGate CLI errors, often due to FortiOS version/features/VDOM scope: "
            + ", ".join(cli_errors)
            + "."
        )

    if "conserve mode: on" in lower:
        findings.append("CRITICAL: FortiGate appears to be in conserve mode. Memory pressure may cause traffic drops.")

    cpu = extract_percent("CPU", full_text)
    mem = extract_percent("memory", full_text)

    if cpu is not None and cpu >= 80:
        findings.append(f"WARNING: High CPU detected around {cpu}%. Check active sessions, UTM, IPS, or traffic spikes.")

    if mem is not None and mem >= 80:
        findings.append(f"WARNING: High memory detected around {mem}%. Watch for conserve mode or service instability.")

    if "denied by forward policy 0" in lower:
        findings.append("POLICY: Traffic may be hitting implicit deny/policy 0. Verify LAN-to-VPN and VPN-to-LAN policies.")

    tunnel_text = get_result_text(results, "diagnose vpn tunnel list").lower()
    if re.search(r"\bstat=0\b", tunnel_text):
        findings.append("VPN: At least one VPN tunnel entry reports stat=0. Verify Phase 1/Phase 2 selectors and peer settings.")

    if re.search(r"\b(?:rx|tx)[_-]?bytes\b|\benc\s+\d+\b|\bdec\s+\d+\b", tunnel_text):
        findings.append("VPN: Tunnel counters collected. During testing, compare whether encrypted/decrypted or TX/RX counters move in both directions.")

    if "set nat enable" in lower:
        findings.append("NAT: NAT is enabled on at least one policy. Confirm VPN traffic is not NATed unless intentionally configured.")

    if "set srcintf" in lower and "set dstintf" in lower:
        findings.append("POLICY: Firewall policies were collected. For VPN incidents, verify both traffic directions, policy order, source/destination objects, services, schedules, and NAT settings.")

    if "version:" in lower or "fortios" in lower:
        findings.append("Firmware info collected. Compare both VPN peers for revision mismatch and known FortiOS bugs.")

    if not findings:
        findings.append("No obvious red flags detected automatically. Review MASTER_LOG.txt manually.")

    return "\n".join(f"- {item}" for item in findings)


def build_cheat_sheet() -> str:
    return """
FortiGate Quick Review Cheat Sheet

1. VPN UP does not always mean traffic is passing.
   - Check tunnel status and TX/RX counters.
   - If TX/encrypted increases but RX/decrypted does not, suspect remote side, return path, selectors, or upstream filtering.
   - If neither moves, traffic may not be matching policy, route, selector, or source/destination objects.

2. A missing firewall policy can look like a VPN problem.
   - Verify LAN-to-VPN and VPN-to-LAN policies both exist where required.
   - Confirm policy order, interfaces/zones, address objects/groups, services, schedules, and NAT.
   - Remember that implicit deny/policy 0 will block traffic even when IKE/IPsec is established.

3. If DNS fails but IP pings also fail, DNS is probably not the primary issue.
   - Check routes, firewall policies, NAT, and VPN selectors first.

4. For site-to-site VPN issues, verify:
   - Phase 1 peer settings
   - Phase 2 local/remote subnets
   - LAN-to-VPN policy
   - VPN-to-LAN policy
   - NAT exemption or intentional forced NAT
   - Static routes if route-based VPN is used
   - Policy rules if policy-based VPN is used

5. If traffic worked before and fails after update/reboot:
   - Check firmware mismatch and recent config changes
   - Check missing or reordered firewall rules
   - Confirm routes, SD-WAN rules, zones, and address objects still match traffic
   - Review recent system events before clearing or bouncing tunnels

6. If vendor escalation is needed, attach:
   - SUMMARY.txt
   - MASTER_LOG.txt
   - firewall firmware versions from both VPN peers
   - exact source/destination IPs and ports tested
   - timestamp and timezone of failed tests
""".strip()


def write_outputs(folder: Path, results: Iterable[CommandResult], target: str, site: str) -> None:
    results = list(results)
    master = []
    for result in results:
        fname = safe_filename(result.command.replace(" ", "_")) + ".txt"
        status = []
        if result.timed_out:
            status.append("TIMED OUT / PARTIAL OUTPUT")
        if result.cli_error:
            status.append("CLI ERROR DETECTED")
        status_text = f"\nSTATUS: {', '.join(status)}" if status else ""
        body = f"COMMAND: {result.command}{status_text}\n\n{result.output}"
        (folder / fname).write_text(body, encoding="utf-8")
        master.append(f"\n\n{'=' * 80}\nCOMMAND: {result.command}{status_text}\n{'=' * 80}\n{result.output}")

    full_text = "".join(master)
    (folder / "MASTER_LOG.txt").write_text(full_text, encoding="utf-8")

    summary = f"""CTS FortiGate Diagnostic Summary
Generated: {datetime.now().isoformat(timespec='seconds')}
Target: {target}
Site: {site}

Automatic Findings:
{analyze(results)}

{build_cheat_sheet()}
"""
    (folder / "SUMMARY.txt").write_text(summary, encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(description="CTS FortiGate Quick Diagnostic Runner")
    parser.add_argument("--host", required=True, help="FortiGate IP/hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--port", type=int, default=22, help="SSH port, default 22")
    parser.add_argument("--name", default="FortiGate", help="Client/site friendly name")
    parser.add_argument("--out", default="fortigate_diagnostics", help="Base output folder")
    parser.add_argument("--command-timeout", type=int, default=30, help="Seconds to wait for each command before saving partial output")
    parser.add_argument("--extended", action="store_true", help="Collect optional IPv6/VDOM/zone context commands")
    parser.add_argument("--strict-host-key", action="store_true", help="Reject unknown SSH host keys instead of auto-adding them")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = Path(args.out) / f"{safe_filename(args.name)}_{timestamp}"
    folder.mkdir(parents=True, exist_ok=True)

    commands = list(CORE_COMMANDS)
    if args.extended:
        commands.extend(EXTENDED_COMMANDS)

    client = None
    try:
        if not args.strict_host_key:
            print("WARNING: Auto-accepting unknown SSH host keys. Use --strict-host-key when known_hosts is managed.", file=sys.stderr)
        print(f"Connecting to {args.host}...")
        client = connect_ssh(args.host, args.user, password, args.port, args.strict_host_key)
        results = run_commands(client, commands, args.command_timeout)
    except Exception as exc:
        if paramiko is not None and isinstance(exc, (paramiko.AuthenticationException, paramiko.BadAuthenticationType)):
            print(f"ERROR: SSH authentication failed: {exc}", file=sys.stderr)
            sys.exit(2)
        if (paramiko is not None and isinstance(exc, paramiko.SSHException)) or isinstance(exc, (socket.timeout, OSError)):
            print(f"ERROR: SSH connection or session failed: {exc}", file=sys.stderr)
            sys.exit(3)
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if client is not None:
            client.close()

    write_outputs(folder, results, args.host, args.name)

    print("\nDone.")
    print(f"Output folder: {folder}")
    print("Start with SUMMARY.txt. Use MASTER_LOG.txt for deeper review or vendor escalation.")


if __name__ == "__main__":
    main()
