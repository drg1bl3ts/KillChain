# AD Attack Chain Runner

BloodHound to shell in copy-paste commands. Maps BloodHound relationships to exact exploitation commands for every hop in the chain — no more Googling mid-engagement.

Zero dependencies beyond Python 3.6+ stdlib. Husky Hacker branding.

---

## Install

```bash
git clone https://github.com/TheHuskyHacker/ADchain
cd adchain
chmod +x adchain.py
sudo ln -s $(pwd)/adchain.py /usr/local/bin/adchain
```

---

## Usage

### Chain Mode — multi-hop attack path

Feed it the chain you see in BloodHound, get every command for every hop:

```bash
# GenericAll → DCSync chain
adchain chain "s.fisher>GenericAll>svc_backup>DCSync>domain" \
  -d corp.local --dc-ip 10.10.10.5 -p 'Welcome1!'

# 3-hop ACL chain
adchain chain "t.brooks>GenericAll>j.nakamura>WriteDACL>svc_backup>DCSync>domain" \
  -d meridian.local --dc-ip 10.10.10.3 -p 'MeridianTemp2024!'

# ForceChangePassword → GMSA → DCSync
adchain chain "helpdesk>ForceChangePassword>svc_sql>ReadGMSAPassword>svc_admin>DCSync>domain" \
  -d corp.local --dc-ip 10.10.10.5 -p 'Password1'
```

Chain format: `source>RELATIONSHIP>target>RELATIONSHIP>target>...`

### Lookup Mode — single relationship

Quick reference for one specific attack:

```bash
adchain lookup GenericAll -s s.fisher -t svc_backup -d corp.local --dc-ip 10.10.10.5 -p 'Welcome1!'
adchain lookup Kerberoasting -d corp.local --dc-ip 10.10.10.5 -s compromised_user -p 'Pass123'
adchain lookup "Pass-the-Hash" -s Administrator -t dc01 -d corp.local -H 'aad3b435b51404eeaad3b435b51404ee'
adchain lookup "Token Impersonation"
```

### Cheatsheet Mode — full AD reference

Dump everything at once, optionally with your domain context filled in:

```bash
adchain cheatsheet
adchain cheatsheet -d corp.local --dc-ip 10.10.10.5
```

### List Mode — see all supported types

```bash
adchain list
```

---

## Supported Relationships

### BloodHound Edges (16)

| Relationship | Risk | What It Means |
|---|---|---|
| GenericAll | CRITICAL | Full control — change password, modify anything |
| GenericWrite | HIGH | Modify attributes — set SPN for Kerberoasting |
| WriteOwner | HIGH | Take ownership → grant yourself GenericAll |
| WriteDACL | HIGH | Modify ACL → grant yourself any permission |
| ForceChangePassword | HIGH | Reset password without knowing current |
| AddMember | HIGH | Add users to the target group |
| DCSync | CRITICAL | Replicate all domain credentials |
| ReadGMSAPassword | HIGH | Read Group Managed Service Account password |
| AllowedToDelegate | HIGH | Constrained delegation — impersonate users |
| AllowedToAct | HIGH | Resource-based constrained delegation (RBCD) |
| SQLAdmin | HIGH | Sysadmin on MSSQL → xp_cmdshell |
| CanPSRemote | MEDIUM | WinRM / Evil-WinRM access |
| CanRDP | MEDIUM | Remote Desktop access |
| HasSIDHistory | CRITICAL | SID History contains privileged SID |
| AddSelf | HIGH | Can add yourself to a group |
| Owns | HIGH | Object owner — can modify DACL |

### Standalone Attacks (10)

| Attack | What It Does |
|---|---|
| Kerberoasting | Crack service account TGS tickets (hashcat -m 13100) |
| AS-REP Roasting | Crack no-preauth accounts (hashcat -m 18200) |
| Password Spray | One password × many accounts |
| Pass-the-Hash | Auth with NTLM hash (psexec/wmiexec/evil-winrm) |
| Coerced Authentication | PetitPotam / PrinterBug + Responder/Inveigh |
| Silver Ticket | Forge service ticket with service hash |
| Golden Ticket | Forge TGT with krbtgt hash — full domain |
| GPO Abuse | Push malicious config via Group Policy |
| Token Impersonation | SeImpersonate → GodPotato/SigmaPotato/PrintSpoofer |
| Service Binary Hijack | sc.exe config binPath abuse |

---

## Tools Referenced

Commands are generated for these tools (install them on your attack box):

- **Impacket** — secretsdump, psexec, wmiexec, getST, GetUserSPNs, GetNPUsers, dacledit, rbcd, addcomputer, ticketer, mssqlclient
- **bloodyAD** — AD object manipulation (password resets, ACL abuse, group membership)
- **Evil-WinRM** — WinRM shell access
- **Rubeus** — Kerberos attacks from Windows
- **Mimikatz** — Credential extraction and ticket forging
- **PowerView** — AD enumeration and ACL abuse from Windows
- **netexec** — SMB/WinRM spraying and lateral movement
- **kerbrute** — Kerberos user enum and password spraying
- **GodPotato / SigmaPotato / PrintSpoofer** — Token impersonation privesc
- **pyGPOAbuse / SharpGPOAbuse** — GPO modification attacks
- **Responder / Inveigh** — Net-NTLMv2 hash capture
- **PetitPotam** — Coerced authentication

---

## License

MIT
