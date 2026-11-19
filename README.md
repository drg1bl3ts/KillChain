# killchain
NOTE: This was inspired by the Husky Hacker and his tool set.

kill-chain tool. One entry point for every phase of an attack: recon through report.

```
killchain [tool] [args]
```

---

## Setup

```bash
bash setup.sh
```

Checks system dependencies, installs pip packages, and creates `/usr/local/bin/killchain`.

---

## Tools

| Command | What it does |
|---------|--------------|
| `recon` | Full auto-recon pipeline (nmap → enum → web) |
| `fruit` | Quick-win finder — services worth hitting first |
| `web` | Web recon (dirs, vhosts, tech fingerprinting) |
| `test` | Web payload testing (SQLi, CMDi, LFI, uploads) |
| `lfi` | LFI fuzzing via ffuf |
| `xfind` | Exploit search (searchsploit + ExploitDB) |
| `shell` | Reverse shell payload generator |
| `privesc` | Linux privesc enumerator (checks + CVEs) |
| `pe` | privesc.sh — bash-based enumeration script |
| `scope` | Scope tracker — target list + local HTTP server |
| `tools` | Download all exam-day tools to ~/oscp-tools/ |
| `pivot` | Pivot command generator (Chisel, Ligolo, SSH) |
| `ad` | AD attack chain (BloodHound paths → commands) |
| `report` | Markdown report generator |

---

## Session State

Save target info once — tools pick it up automatically:

```bash
killchain session set --target 10.10.10.5 --attacker 10.10.14.2
killchain session set --user admin --pass 'P@ssw0rd' --domain corp.local --dc 10.10.10.5
killchain session show
killchain session clear
```

State lives in `~/.oscp_session.json`.

---

## Workflow

Print the full kill chain with your session values filled in:

```bash
killchain workflow
```

---

## Common Exam Flow

```bash
# 1. Set your target
killchain session set --target 192.168.1.10 --attacker 10.10.14.2

# 2. Initial recon
killchain recon 192.168.1.10

# 3. Quick wins
killchain fruit 192.168.1.10

# 4. Web if applicable
killchain web -u http://192.168.1.10

# 5. Get a shell
killchain shell -i 10.10.14.2 -p 4444 bash

# 6. Privesc
killchain pe    # drops to bash script
killchain privesc 192.168.1.10

# 7. Report
killchain report
```

---

## Directory Layout

```
Methodology/
├── killchain.py          # entry point
├── setup.sh              # first-run setup
├── Recon/
│   ├── recon.py          # full recon pipeline
│   ├── fruitpicker.py    # quick-win finder
│   ├── webrecon.py       # web recon
│   ├── webtester.py      # payload testing
│   ├── lfi_scan.sh       # LFI fuzzer
│   └── xfind.py          # exploit finder
├── RevShell/
│   └── revshell.py       # reverse shell factory
├── PrivEsc/
│   ├── privesc.py        # Python privesc enumerator
│   ├── privesc.sh        # bash privesc script
│   ├── scope.sh          # scope tracker
│   └── toolbox.sh        # tool downloader
├── Pivot/
│   └── pivot.py          # pivot planner
├── ADchain/
│   └── adchain.py        # AD attack chain
└── Report/
    └── report.py         # report generator
```

---

## Dependencies

Python: `python-nmap requests urllib3`

System: `nmap gobuster ffuf nikto wfuzz searchsploit curl netcat`

Wordlists: SecLists at `/opt/lists/seclists/` (Exegol) or `/usr/share/seclists/` (Kali)
