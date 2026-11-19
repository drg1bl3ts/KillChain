#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Toolbox — downloads all PEN-200 privesc & AD
# tools for Linux and Windows targets. Run once on your
# attacker box before the exam.
#
# Creates: ~/oscp-tools/ with organized subdirectories
#
# Usage: chmod +x toolbox.sh && ./toolbox.sh
#        or: ./toolbox.sh /custom/path
# ═══════════════════════════════════════════════════════════

TOOLS_DIR="${1:-$HOME/oscp-tools}"

RED='\033[91m' GRN='\033[92m' YEL='\033[93m'
CYN='\033[96m' BLD='\033[1m'  DIM='\033[2m'  RST='\033[0m'

echo -e "\n${BLD}${CYN}═══════════════════════════════════════${RST}"
echo -e "  ${BLD}TOOLBOX${RST}"
echo -e "${BLD}${CYN}═══════════════════════════════════════${RST}"
echo -e "  ${DIM}Target: $TOOLS_DIR${RST}\n"

DOWNLOADED=0; FAILED=0; SKIPPED=0

grab() {
    local url="$1" dest="$2" desc="$3"
    local filename=$(basename "$dest")
    if [ -f "$dest" ]; then
        echo -e "  ${DIM}[*]${RST} ${filename} — already have it"
        ((SKIPPED++)); return 0
    fi
    echo -ne "  ${DIM}[*]${RST} ${desc:-$filename}..."
    if curl -sL --fail --connect-timeout 10 --max-time 120 -o "$dest" "$url" 2>/dev/null; then
        local size=$(stat -c%s "$dest" 2>/dev/null || stat -f%z "$dest" 2>/dev/null || echo 0)
        if [ "${size:-0}" -gt 100 ] 2>/dev/null; then
            echo -e " ${GRN}OK${RST} (${size} bytes)"
            ((DOWNLOADED++))
        else
            echo -e " ${RED}EMPTY${RST}"; rm -f "$dest"; ((FAILED++))
        fi
    else
        echo -e " ${RED}FAIL${RST}"; rm -f "$dest"; ((FAILED++))
    fi
}

section() { echo -e "\n  ${BLD}${CYN}═══ $1 ═══${RST}"; }

mkdir -p "$TOOLS_DIR"/{linux,windows/potatoes,windows/sharp,ad,web,pivoting,misc}

# ═══════ LINUX PRIVESC ═══════
section "Linux Privilege Escalation"
grab "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" "$TOOLS_DIR/linux/linpeas.sh" "linPEAS"
grab "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "$TOOLS_DIR/linux/linux-exploit-suggester.sh" "linux-exploit-suggester"
grab "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" "$TOOLS_DIR/linux/linux-exploit-suggester-2.pl" "linux-exploit-suggester-2"
grab "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" "$TOOLS_DIR/linux/LinEnum.sh" "LinEnum"
grab "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" "$TOOLS_DIR/linux/lse.sh" "Linux Smart Enumeration"
grab "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" "$TOOLS_DIR/linux/pspy64" "pspy64"
grab "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" "$TOOLS_DIR/linux/pspy32" "pspy32"
grab "https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py" "$TOOLS_DIR/linux/pwnkit.py" "PwnKit CVE-2021-4034"
grab "https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py" "$TOOLS_DIR/linux/linuxprivchecker.py" "linuxprivchecker"
# unix-privesc-check removed — pentestmonkey repo restructured, URL no longer works

# ═══════ WINDOWS PRIVESC ═══════
section "Windows Privilege Escalation"
grab "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" "$TOOLS_DIR/windows/winPEASx64.exe" "winPEAS x64"
grab "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" "$TOOLS_DIR/windows/winPEASx86.exe" "winPEAS x86"
grab "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat" "$TOOLS_DIR/windows/winPEAS.bat" "winPEAS bat"
grab "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe" "$TOOLS_DIR/windows/potatoes/GodPotato-NET4.exe" "GodPotato NET4"
grab "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET2.exe" "$TOOLS_DIR/windows/potatoes/GodPotato-NET2.exe" "GodPotato NET2"
grab "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe" "$TOOLS_DIR/windows/potatoes/PrintSpoofer64.exe" "PrintSpoofer x64"
grab "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer32.exe" "$TOOLS_DIR/windows/potatoes/PrintSpoofer32.exe" "PrintSpoofer x32"
grab "https://github.com/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe" "$TOOLS_DIR/windows/potatoes/SigmaPotato.exe" "SigmaPotato"
grab "https://github.com/ohpe/juicy-potato/releases/latest/download/JuicyPotato.exe" "$TOOLS_DIR/windows/potatoes/JuicyPotato.exe" "JuicyPotato"
grab "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" "$TOOLS_DIR/windows/PowerUp.ps1" "PowerUp.ps1"
# PrivescCheck.ps1 removed — itm4n repo restructured, raw URL no longer works; install manually from https://github.com/itm4n/PrivescCheck/releases
grab "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe" "$TOOLS_DIR/windows/sharp/SharpUp.exe" "SharpUp"
grab "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" "$TOOLS_DIR/windows/sharp/Seatbelt.exe" "Seatbelt"
grab "https://github.com/itm4n/FullPowers/releases/latest/download/FullPowers.exe" "$TOOLS_DIR/windows/FullPowers.exe" "FullPowers"
grab "https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip" "$TOOLS_DIR/windows/RunasCs.zip" "RunasCs"
grab "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" "$TOOLS_DIR/windows/nc64.exe" "nc64.exe"
grab "https://github.com/int0x33/nc.exe/raw/master/nc.exe" "$TOOLS_DIR/windows/nc.exe" "nc.exe (32-bit)"
grab "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1" "$TOOLS_DIR/windows/powercat.ps1" "powercat.ps1"

# ═══════ ACTIVE DIRECTORY ═══════
section "Active Directory"
grab "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" "$TOOLS_DIR/ad/mimikatz_trunk.zip" "Mimikatz"
grab "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" "$TOOLS_DIR/ad/Rubeus.exe" "Rubeus"
grab "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe" "$TOOLS_DIR/ad/Certify.exe" "Certify"
# Whisker removed — not in r3motecontrol Ghostpack compiled binaries repo; get from https://github.com/eladshamir/Whisker/releases
grab "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" "$TOOLS_DIR/ad/PowerView.ps1" "PowerView.ps1"
grab "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" "$TOOLS_DIR/ad/Invoke-PowerShellTcp.ps1" "Nishang Invoke-PowerShellTcp"
echo -ne "  ${DIM}[*]${RST} Fetching Inveigh latest version..."
INVEIGH_URL=$(curl -s --max-time 8 "https://api.github.com/repos/Kevin-Robertson/Inveigh/releases/latest" 2>/dev/null | python3 -c "import sys,json; r=json.load(sys.stdin); urls=[a['browser_download_url'] for a in r.get('assets',[]) if 'win-x64-nativeaot' in a['name']]; print(urls[0] if urls else '')" 2>/dev/null)
if [ -n "$INVEIGH_URL" ]; then
    INVEIGH_FILE=$(basename "$INVEIGH_URL")
    echo -e " ${DIM}$(echo "$INVEIGH_URL" | grep -oP 'v[\d.]+')${RST}"
    grab "$INVEIGH_URL" "$TOOLS_DIR/ad/$INVEIGH_FILE" "Inveigh (Windows nativeaot)"
else
    echo -e " ${YEL}SKIP${RST}"; ((SKIPPED++))
fi
grab "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" "$TOOLS_DIR/ad/kerbrute" "kerbrute"
# pyGPOAbuse removed — Hackndo repo restructured; install via: pip install pygpoabuse
grab "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe" "$TOOLS_DIR/ad/LaZagne.exe" "LaZagne"

# ═══════ PIVOTING ═══════
section "Pivoting"
grab "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" "$TOOLS_DIR/pivoting/socat_static" "socat (static Linux)"
grab "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap" "$TOOLS_DIR/pivoting/nmap_static" "nmap (static Linux)"

# Chisel — try to get latest
echo -ne "  ${DIM}[*]${RST} Fetching chisel latest version..."
CHISEL_VER=$(curl -sI https://github.com/jpillora/chisel/releases/latest 2>/dev/null | grep -i location | grep -oP 'v[\d.]+' || echo "v1.10.1")
echo -e " ${CHISEL_VER}"
grab "https://github.com/jpillora/chisel/releases/download/${CHISEL_VER}/chisel_${CHISEL_VER#v}_linux_amd64.gz" "$TOOLS_DIR/pivoting/chisel_linux.gz" "Chisel Linux"
grab "https://github.com/jpillora/chisel/releases/download/${CHISEL_VER}/chisel_${CHISEL_VER#v}_windows_amd64.zip" "$TOOLS_DIR/pivoting/chisel_windows.zip" "Chisel Windows"

# Decompress chisel Linux (.gz), extract chisel Windows (.zip)
[ -f "$TOOLS_DIR/pivoting/chisel_linux.gz" ] && [ ! -f "$TOOLS_DIR/pivoting/chisel_linux" ] && gunzip -k "$TOOLS_DIR/pivoting/chisel_linux.gz" 2>/dev/null
[ -f "$TOOLS_DIR/pivoting/chisel_windows.zip" ] && [ ! -f "$TOOLS_DIR/pivoting/chisel.exe" ] && unzip -q -o "$TOOLS_DIR/pivoting/chisel_windows.zip" -d "$TOOLS_DIR/pivoting/" 2>/dev/null && mv "$TOOLS_DIR/pivoting/chisel_"*".exe" "$TOOLS_DIR/pivoting/chisel.exe" 2>/dev/null

# Ligolo-ng
echo -ne "  ${DIM}[*]${RST} Fetching ligolo-ng latest version..."
LIGOLO_VER=$(curl -sI https://github.com/nicocha30/ligolo-ng/releases/latest 2>/dev/null | grep -i location | grep -oP 'v[\d.]+' || echo "v0.8.2")
echo -e " ${LIGOLO_VER}"
grab "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER#v}_linux_amd64.tar.gz" "$TOOLS_DIR/pivoting/ligolo_proxy.tar.gz" "Ligolo proxy (Linux)"
grab "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER#v}_linux_amd64.tar.gz" "$TOOLS_DIR/pivoting/ligolo_agent_linux.tar.gz" "Ligolo agent (Linux)"
grab "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER#v}_windows_amd64.zip" "$TOOLS_DIR/pivoting/ligolo_agent_windows.zip" "Ligolo agent (Windows)"

# Extract ligolo
for tar in "$TOOLS_DIR"/pivoting/ligolo_*.tar.gz; do
    [ -f "$tar" ] && tar xzf "$tar" -C "$TOOLS_DIR/pivoting/" 2>/dev/null
done

# ═══════ WEB SHELLS ═══════
section "Web Exploitation"
grab "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" "$TOOLS_DIR/web/php-reverse-shell.php" "PHP reverse shell"
grab "https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php" "$TOOLS_DIR/web/p0wny-shell.php" "p0wny-shell"
grab "https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php" "$TOOLS_DIR/web/wwwolf-webshell.php" "wwwolf webshell"

# ═══════ MISC ═══════
section "Misc"
grab "https://raw.githubusercontent.com/brightio/penelope/main/penelope.py" "$TOOLS_DIR/misc/penelope.py" "penelope (rev shell handler)"

# ═══════ Set permissions ═══════
chmod +x "$TOOLS_DIR"/linux/*.sh "$TOOLS_DIR"/linux/*.pl 2>/dev/null
chmod +x "$TOOLS_DIR"/linux/pspy* 2>/dev/null
chmod +x "$TOOLS_DIR"/pivoting/chisel_linux "$TOOLS_DIR"/pivoting/socat_static "$TOOLS_DIR"/pivoting/nmap_static 2>/dev/null
chmod +x "$TOOLS_DIR"/pivoting/proxy "$TOOLS_DIR"/pivoting/agent 2>/dev/null
chmod +x "$TOOLS_DIR"/ad/kerbrute 2>/dev/null
chmod +x "$TOOLS_DIR"/misc/penelope.py 2>/dev/null

# ═══════ PIP REMINDER ═══════
section "Pip Packages (install separately)"
echo -e "  ${CYN}pip install impacket${RST}             # secretsdump, psexec, getST"
echo -e "  ${CYN}pip install bloodyAD${RST}             # AD object manipulation"
echo -e "  ${CYN}pip install bloodhound${RST}           # Python BloodHound collector"
echo -e "  ${CYN}pip install certipy-ad${RST}           # AD certificate abuse"
echo -e "  ${CYN}pip install pygpoabuse${RST}           # GPO abuse"
echo -e "  ${CYN}gem install evil-winrm${RST}           # WinRM shell"
echo -e "  ${CYN}sudo apt install seclists${RST}        # Wordlists"
echo -e "  ${DIM}# PrivescCheck: https://github.com/itm4n/PrivescCheck/releases${RST}"
echo -e "  ${DIM}# Whisker:      https://github.com/eladshamir/Whisker/releases${RST}"

# ═══════ SUMMARY ═══════
section "Summary"
TOTAL=$(find "$TOOLS_DIR" -type f | wc -l)
echo ""
echo -e "  ${GRN}Downloaded: ${DOWNLOADED}${RST}  ${YEL}Skipped: ${SKIPPED}${RST}  ${RED}Failed: ${FAILED}${RST}  ${BLD}Total: ${TOTAL} files${RST}"
echo ""
echo -e "  ${DIM}├── linux/${RST}              linPEAS, pspy, exploit-suggester, LinEnum"
echo -e "  ${DIM}├── windows/${RST}            winPEAS, PowerUp, nc.exe, RunasCs"
echo -e "  ${DIM}│   ├── potatoes/${RST}       GodPotato, PrintSpoofer, SigmaPotato, JuicyPotato"
echo -e "  ${DIM}│   └── sharp/${RST}          SharpUp, Seatbelt"
echo -e "  ${DIM}├── ad/${RST}                 Mimikatz, Rubeus, Certify, PowerView, Inveigh, kerbrute"
echo -e "  ${DIM}├── web/${RST}                PHP reverse shell, webshells"
echo -e "  ${DIM}├── pivoting/${RST}           Chisel, Ligolo-ng, socat, static nmap"
echo -e "  ${DIM}└── misc/${RST}               LaZagne, penelope"
echo ""
echo -e "  ${BLD}Exam day — serve them:${RST}"
echo -e "    ${CYN}cd $TOOLS_DIR && python3 -m http.server 8000${RST}"
echo ""
