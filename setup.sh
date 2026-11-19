#!/bin/bash
# killchain setup
# Checks tools, installs missing ones, creates venv, symlinks killchain.
# Supports: Arch Linux (pacman/yay), Kali/Debian/Ubuntu (apt), Fedora/RHEL (dnf)

RED='\033[91m' GRN='\033[92m' YEL='\033[93m'
CYN='\033[96m' BLD='\033[1m'  DIM='\033[2m'  RST='\033[0m'

echo -e "\n${BLD}${CYN}═══════════════════════════════════════${RST}"
echo -e "  ${BLD}SETUP${RST}"
echo -e "${BLD}${CYN}═══════════════════════════════════════${RST}\n"

PASS=0; WARN=0; FAIL=0
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()      { echo -e "  ${GRN}[OK]${RST}   $1"; ((PASS++)); }
warn()    { echo -e "  ${YEL}[WARN]${RST} $1"; ((WARN++)); }
miss()    { echo -e "  ${RED}[MISS]${RST} $1"; ((FAIL++)); }
info()    { echo -e "  ${DIM}[*]${RST}   $1"; }
section() { echo -e "\n  ${BLD}${CYN}─── $1 ───${RST}"; }

# ─── Package manager detection ───────────────────────────────────────────────
PM="unknown"
AUR_HELPER=""
command -v pacman  &>/dev/null && PM="pacman"
command -v apt-get &>/dev/null && PM="apt"
command -v dnf     &>/dev/null && PM="dnf"
[ "$PM" = "pacman" ] && {
    command -v yay  &>/dev/null && AUR_HELPER="yay"
    command -v paru &>/dev/null && [ -z "$AUR_HELPER" ] && AUR_HELPER="paru"
}
info "Package manager: ${BLD}$PM${RST}${AUR_HELPER:+  AUR: $AUR_HELPER}"

# ─── Install queues ───────────────────────────────────────────────────────────
SYS_PKG=()
AUR_PKG=()
PIPX_PKG=()
GEM_PKG=()
DO_KERBRUTE=0

# tool_check <cmd> <pacman_pkg> <apt_pkg> <dnf_pkg>
tool_check() {
    local cmd=$1 pacman_pkg=$2 apt_pkg=$3 dnf_pkg=$4
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd — $(command -v "$cmd")"; return 0
    fi
    miss "$cmd not found"
    case "$PM" in
        pacman) [ -n "$pacman_pkg" ] && SYS_PKG+=("$pacman_pkg") ;;
        apt)    [ -n "$apt_pkg"    ] && SYS_PKG+=("$apt_pkg")    ;;
        dnf)    [ -n "$dnf_pkg"    ] && SYS_PKG+=("$dnf_pkg")    ;;
    esac
}

# aur_check <cmd> <aur_pkg> <apt_pkg> <dnf_pkg>
# On Arch queues AUR; on apt/dnf queues system package.
aur_check() {
    local cmd=$1 aur_pkg=$2 apt_pkg=$3 dnf_pkg=$4
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd — $(command -v "$cmd")"; return 0
    fi
    miss "$cmd not found"
    case "$PM" in
        pacman) [ -n "$aur_pkg" ] && AUR_PKG+=("$aur_pkg") ;;
        apt)    [ -n "$apt_pkg" ] && SYS_PKG+=("$apt_pkg") ;;
        dnf)    [ -n "$dnf_pkg" ] && SYS_PKG+=("$dnf_pkg") ;;
    esac
}

# pipx_check <cmd> <package>
pipx_check() {
    local cmd=$1 pkg=$2
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd — $(command -v "$cmd")"; return 0
    fi
    miss "$cmd not found"
    [[ " ${PIPX_PKG[*]} " == *" $pkg "* ]] || PIPX_PKG+=("$pkg")
}

# gem_check <cmd> <gem>
gem_check() {
    local cmd=$1 gem=$2
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd — $(command -v "$cmd")"; return 0
    fi
    miss "$cmd not found"
    GEM_PKG+=("$gem")
}

# ─── System Tools ─────────────────────────────────────────────────────────────
section "System Tools"

# Core
tool_check python3      "python"           "python3"            "python3"
tool_check pip3         "python-pip"       "python3-pip"        "python3-pip"
tool_check nmap         "nmap"             "nmap"               "nmap"
tool_check curl         "curl"             "curl"               "curl"
tool_check nc           "openbsd-netcat"   "netcat-traditional" "nmap-ncat"

# Web
tool_check ffuf         "ffuf"             "ffuf"               ""
tool_check feroxbuster  "feroxbuster"      "feroxbuster"        ""
tool_check gobuster     "gobuster"         "gobuster"           "gobuster"
tool_check nikto        "nikto"            "nikto"              "nikto"
tool_check whatweb      "whatweb"          "whatweb"            ""

# Enum
tool_check smbclient    "smbclient"        "smbclient"          "samba-client"
tool_check snmpwalk     "net-snmp"         "snmp"               "net-snmp"
tool_check dig          "bind"             "dnsutils"           "bind-utils"
tool_check ldapsearch   "openldap"         "ldap-utils"         "openldap-clients"
tool_check searchsploit "exploitdb"        "exploitdb"          ""
tool_check socat        "socat"            "socat"              "socat"
tool_check ssh          "openssh"          "openssh-client"     "openssh"

# enum4linux — accept -ng variant too
if command -v enum4linux-ng &>/dev/null; then
    ok "enum4linux-ng — $(command -v enum4linux-ng)"
elif command -v enum4linux &>/dev/null; then
    ok "enum4linux — $(command -v enum4linux)"
else
    miss "enum4linux not found"
    case "$PM" in
        pacman) AUR_PKG+=("enum4linux-ng") ;;
        apt)    SYS_PKG+=("enum4linux") ;;
    esac
fi

# netexec — binary is 'nxc'; official install: pipx install git+https://github.com/Pennyw0rth/NetExec
# (AUR PKGBUILD is broken on Python 3.14+ due to certipy-ad/certipy-nxc naming conflict)
if command -v nxc &>/dev/null; then
    ok "nxc/netexec — $(command -v nxc)"
elif command -v netexec &>/dev/null; then
    ok "netexec — $(command -v netexec)"
elif command -v crackmapexec &>/dev/null; then
    ok "crackmapexec — $(command -v crackmapexec) [deprecated, nxc preferred]"
else
    miss "nxc/netexec not found"
    [[ " ${PIPX_PKG[*]} " == *" git+https://github.com/Pennyw0rth/NetExec "* ]] || \
        PIPX_PKG+=("git+https://github.com/Pennyw0rth/NetExec")
fi

# kerbrute — check PATH then oscp-tools download dir
if command -v kerbrute &>/dev/null; then
    ok "kerbrute — $(command -v kerbrute)"
elif [ -x "$HOME/oscp-tools/ad/kerbrute" ]; then
    ok "kerbrute — $HOME/oscp-tools/ad/kerbrute (not on PATH — will symlink)"
    DO_KERBRUTE=1
else
    miss "kerbrute not found — run: killchain tools to download, then re-run setup.sh"
fi

# impacket suite — command name varies by install method
# pipx install: impacket-secretsdump | Arch system package: secretsdump.py
if command -v impacket-secretsdump &>/dev/null; then
    ok "impacket — $(command -v impacket-secretsdump)"
elif command -v secretsdump.py &>/dev/null; then
    ok "impacket — $(command -v secretsdump.py)"
elif command -v secretsdump &>/dev/null; then
    ok "impacket — $(command -v secretsdump)"
else
    miss "impacket not found (secretsdump, psexec, getTGT, etc.)"
    PIPX_PKG+=("impacket")
fi

# evil-winrm (Ruby gem; Kali also has it in apt)
if command -v evil-winrm &>/dev/null; then
    ok "evil-winrm — $(command -v evil-winrm)"
else
    miss "evil-winrm not found"
    [ "$PM" = "apt" ] && SYS_PKG+=("evil-winrm") || GEM_PKG+=("evil-winrm")
fi

# bloodhound-python
pipx_check bloodhound-python bloodhound

# penelope reverse shell handler
if command -v penelope &>/dev/null; then
    ok "penelope — $(command -v penelope)"
elif [ -f "$HOME/oscp-tools/misc/penelope.py" ]; then
    ok "penelope — $HOME/oscp-tools/misc/penelope.py"
else
    miss "penelope not found — run: killchain tools to download"
fi

# Report tools
tool_check pandoc       "pandoc-cli"       "pandoc"             "pandoc"
tool_check xelatex      "texlive-xetex"    "texlive-xetex"      "texlive"

# ─── Wordlists ────────────────────────────────────────────────────────────────
section "Wordlists"

SECLISTS_PATHS=(
    "/opt/lists/seclists"
    "/usr/share/seclists"
    "/usr/share/wordlists/seclists"
    "$HOME/SecLists"
    "/opt/seclists"
)
SECLISTS_FOUND=""
for p in "${SECLISTS_PATHS[@]}"; do
    if [ -d "$p" ]; then SECLISTS_FOUND="$p"; break; fi
done
if [ -n "$SECLISTS_FOUND" ]; then
    ok "SecLists found — $SECLISTS_FOUND"
else
    warn "SecLists not found"
    case "$PM" in
        apt)    info "Install: sudo apt install seclists" ;;
        pacman) info "Install: yay -S seclists  OR  git clone https://github.com/danielmiessler/SecLists ~/SecLists" ;;
        dnf)    info "Install: git clone https://github.com/danielmiessler/SecLists ~/SecLists" ;;
    esac
fi

ROCKYOU_PATHS=(
    "/opt/lists/rockyou.txt"
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    "/usr/share/wordlists/rockyou.txt.gz"
)
ROCKYOU_FOUND=""
for p in "${ROCKYOU_PATHS[@]}"; do
    if [ -f "$p" ]; then ROCKYOU_FOUND="$p"; break; fi
done
if [ -n "$ROCKYOU_FOUND" ]; then
    ok "rockyou found — $ROCKYOU_FOUND"
else
    warn "rockyou not found"
    info "Try: sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz"
fi

# ─── Python Virtual Environment ───────────────────────────────────────────────
section "Python Virtual Environment"

VENV_DIR="$DIR/.venv"
DEPS=(python-nmap requests urllib3)

if [ -d "$VENV_DIR" ]; then
    ok "Venv exists — $VENV_DIR"
else
    info "Creating venv at $VENV_DIR ..."
    if python3 -m venv "$VENV_DIR" 2>/dev/null; then
        ok "Venv created"
    else
        miss "python3 -m venv failed"
        case "$PM" in
            pacman) info "Fix: sudo pacman -S python" ;;
            apt)    info "Fix: sudo apt install python3-venv" ;;
            dnf)    info "Fix: sudo dnf install python3" ;;
        esac
    fi
fi

if [ -d "$VENV_DIR" ]; then
    info "Installing into venv: ${DEPS[*]}"
    if "$VENV_DIR/bin/pip" install --quiet "${DEPS[@]}" 2>/dev/null; then
        ok "Installed: ${DEPS[*]}"
    else
        warn "pip install into venv failed — try: $VENV_DIR/bin/pip install ${DEPS[*]}"
    fi
    for check in "nmap:python-nmap" "requests:requests" "urllib3:urllib3"; do
        mod="${check%%:*}"; pkg="${check##*:}"
        if "$VENV_DIR/bin/python3" -c "import $mod" &>/dev/null; then
            ok "venv: $pkg importable"
        else
            warn "venv: $pkg not importable after install"
        fi
    done
fi

# ─── killchain Command ────────────────────────────────────────────────────────
section "killchain Command"

KILLCHAIN="$DIR/killchain.py"
if [ -f "$KILLCHAIN" ]; then
    chmod +x "$KILLCHAIN"
    if [ -L /usr/local/bin/killchain ] || command -v killchain &>/dev/null; then
        ok "killchain — $(command -v killchain 2>/dev/null || echo /usr/local/bin/killchain)"
    elif [ -w /usr/local/bin ]; then
        ln -sf "$KILLCHAIN" /usr/local/bin/killchain
        ok "Symlinked killchain → /usr/local/bin/killchain"
    elif sudo -n true 2>/dev/null; then
        sudo ln -sf "$KILLCHAIN" /usr/local/bin/killchain
        ok "Symlinked killchain → /usr/local/bin/killchain (sudo)"
    else
        warn "No write access to /usr/local/bin — add manually:"
        info "  sudo ln -sf $KILLCHAIN /usr/local/bin/killchain"
        info "  OR add to PATH: export PATH=\"\$PATH:$DIR\""
    fi
else
    miss "killchain.py not found in $DIR"
fi

# ─── Auto-Install Missing Tools ───────────────────────────────────────────────
do_install() {
    section "Installing"

    # System packages (pacman/apt/dnf)
    if [ ${#SYS_PKG[@]} -gt 0 ]; then
        info "System packages: ${SYS_PKG[*]}"
        case "$PM" in
            pacman) sudo pacman -S --needed --noconfirm "${SYS_PKG[@]}" \
                        && ok "Installed: ${SYS_PKG[*]}" || warn "Some packages failed" ;;
            apt)    sudo apt-get install -y "${SYS_PKG[@]}" \
                        && ok "Installed: ${SYS_PKG[*]}" || warn "Some packages failed" ;;
            dnf)    sudo dnf install -y "${SYS_PKG[@]}" \
                        && ok "Installed: ${SYS_PKG[*]}" || warn "Some packages failed" ;;
        esac
    fi

    # AUR packages (Arch only)
    if [ ${#AUR_PKG[@]} -gt 0 ]; then
        if [ -n "$AUR_HELPER" ]; then
            info "AUR packages: ${AUR_PKG[*]}"
            "$AUR_HELPER" -S --needed --noconfirm "${AUR_PKG[@]}" \
                && ok "AUR installed: ${AUR_PKG[*]}" || warn "Some AUR packages failed"
        else
            warn "AUR packages need yay or paru: ${AUR_PKG[*]}"
            info "Install yay: pacman -S --needed git base-devel && git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si"
        fi
    fi

    # pipx packages
    if [ ${#PIPX_PKG[@]} -gt 0 ]; then
        if ! command -v pipx &>/dev/null; then
            info "Installing pipx..."
            case "$PM" in
                pacman) sudo pacman -S --noconfirm python-pipx ;;
                apt)    sudo apt-get install -y pipx ;;
                dnf)    sudo dnf install -y pipx ;;
                *)      pip3 install --user pipx ;;
            esac
            export PATH="$HOME/.local/bin:$PATH"
        fi
        for pkg in "${PIPX_PKG[@]}"; do
            info "pipx install $pkg"
            pipx install "$pkg" && ok "$pkg installed" \
                || warn "$pkg failed — try manually: pipx install $pkg"
        done
    fi

    # Ruby gems
    if [ ${#GEM_PKG[@]} -gt 0 ]; then
        if ! command -v gem &>/dev/null; then
            info "Installing ruby..."
            case "$PM" in
                pacman) sudo pacman -S --noconfirm ruby ;;
                apt)    sudo apt-get install -y ruby-full ;;
                dnf)    sudo dnf install -y ruby ;;
            esac
        fi
        for g in "${GEM_PKG[@]}"; do
            info "gem install $g"
            gem install "$g" && ok "$g installed" || warn "$g failed"
        done
    fi

    # Kerbrute symlink
    if [ "$DO_KERBRUTE" = "1" ] && [ -x "$HOME/oscp-tools/ad/kerbrute" ]; then
        sudo ln -sf "$HOME/oscp-tools/ad/kerbrute" /usr/local/bin/kerbrute \
            && ok "kerbrute symlinked → /usr/local/bin/kerbrute"
    fi

    echo ""
    info "Re-run setup.sh to verify all tools are installed"
}

TOTAL_PENDING=$(( ${#SYS_PKG[@]} + ${#AUR_PKG[@]} + ${#PIPX_PKG[@]} + ${#GEM_PKG[@]} + DO_KERBRUTE ))
if [ "$TOTAL_PENDING" -gt 0 ]; then
    echo ""
    section "Missing — Ready to Install"
    [ ${#SYS_PKG[@]}  -gt 0 ] && info "$PM:    ${SYS_PKG[*]}"
    [ ${#AUR_PKG[@]}  -gt 0 ] && info "AUR:   ${AUR_PKG[*]}"
    [ ${#PIPX_PKG[@]} -gt 0 ] && info "pipx:  ${PIPX_PKG[*]}"
    [ ${#GEM_PKG[@]}  -gt 0 ] && info "gem:   ${GEM_PKG[*]}"
    [ "$DO_KERBRUTE" = "1"   ] && info "symlink: kerbrute → /usr/local/bin/kerbrute"
    echo ""
    echo -ne "  Install $TOTAL_PENDING missing item(s) now? [y/N]: "
    read -r choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        do_install
    fi
fi

# ─── OSCP Tools Download ──────────────────────────────────────────────────────
section "OSCP Tools Download"

TOOLBOX="$DIR/PrivEsc/toolbox.sh"
if [ -f "$TOOLBOX" ]; then
    echo -ne "  Download Windows/AD/pivoting tools to ~/oscp-tools/? [y/N]: "
    read -r choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        bash "$TOOLBOX"
    else
        info "Skipped — run manually: bash PrivEsc/toolbox.sh"
    fi
else
    miss "toolbox.sh not found"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}${CYN}─── Summary ───${RST}"
echo -e "  ${GRN}OK:${RST} $PASS   ${YEL}WARN:${RST} $WARN   ${RED}MISS:${RST} $FAIL"
echo ""
[ "$FAIL" -gt 0 ] && echo -e "  ${YEL}[!]${RST} See MISS items above — select 'y' at the install prompt to fix."
echo -e "  ${GRN}[+]${RST} Run: ${BLD}killchain workflow${RST}"
echo ""
