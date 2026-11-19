# Pivot Plumber

Right tunnel. Right interface. Every time. Generates exact commands for both attacker and target sides across Ligolo-ng, Chisel, SSH tunnels, and sshuttle — with callback guidance so you stop catching shells on the wrong interface.

Zero dependencies beyond Python 3.6+ stdlib. Husky Hacker branding.

---

## Install


git clone h# Pivot Plumber

Right tunnel. Right interface. Every time. Generates exact commands for both attacker and target sides across Ligolo-ng, Chisel, SSH tunnels, and sshuttle — with callback guidance so you stop catching shells on the wrong interface.

Zero dependencies beyond Python 3.6+ stdlib. Husky Hacker branding.


## Install

```bash
git clone https://github.com/TheHuskyHacker/piviot-python
cd pivot-python
chmod +x pivot.py
sudo ln -s $(pwd)/pivot.py /usr/local/bin/pivot
```

---

## Usage

```bash
# Ligolo-ng full setup
pivot ligolo -a 10.10.15.110 -p 172.16.139.10 -n 172.16.139.0/24

# Ligolo with double pivot
pivot ligolo -a 10.10.15.110 -p 172.16.139.10 -n 172.16.139.0/24 --double --double-net 10.10.0.0/24

# Chisel SOCKS + port forward
pivot chisel -a 10.10.15.110 -p 10.10.10.5

# SSH tunnels
pivot ssh -p 10.10.10.5 -u developer

# sshuttle transparent proxy
pivot sshuttle -p 10.10.10.5 -u admin -n 10.0.0.0/24

# Full cheatsheet — all methods side by side
pivot cheatsheet

# Check your interfaces
pivot interfaces
```

---

## What Each Mode Gives You

### `pivot ligolo`
Step-by-step Ligolo-ng setup: TUN interface creation, route addition, proxy start, agent transfer (Linux + Windows), session selection, connectivity verification, and **callback guidance** (which IP to use for reverse shells from internal hosts). Includes double-pivot instructions with `--double`.

### `pivot chisel`
Chisel SOCKS proxy and port forward commands for both attacker and target. Includes agent transfer, proxychains config, and callback routing options.

### `pivot ssh`
Dynamic SOCKS proxy (`-D`), local port forward (`-L`), remote port forward (`-R`), and key-based variants. No binary transfer needed.

### `pivot sshuttle`
Transparent TCP routing — no proxychains needed. Single and multi-subnet, with exclusion rules.

### `pivot cheatsheet`
All four methods plus a comparison table and the **5 common gotchas** that have burned you before.

### `pivot interfaces`
Auto-detects your network interfaces and IPs — shows which one to use for target callbacks.

---

## Options

| Flag | Short | Description | Default |
|---|---|---|---|
| `--attacker-ip` | `-a` | Your attacker IP (tun0) | auto-detect |
| `--pivot-ip` | `-p` | Pivot host IP | — |
| `--internal-net` | `-n` | Internal subnet to reach | 172.16.0.0/24 |
| `--pivot-user` | `-u` | SSH user on pivot | user |
| `--listen-port` | | Listener port | varies |
| `--socks-port` | | SOCKS proxy port | 1080 |
| `--tun-name` | | Ligolo TUN name | ligolo |
| `--double` | | Include double-pivot guidance | off |
| `--double-net` | | Second internal network | 10.10.0.0/24 |

---

## The 5 Gotchas This Tool Prevents

1. **Listeners on the wrong IP** — internal hosts can't route to your tun0/VPN. The tool prints exactly which IP to use for callbacks.

2. **nmap through SOCKS** — must use `-sT` (connect scan), not `-sS` (SYN scan). SYN scans don't work through SOCKS proxies.

3. **Stale Ligolo interfaces** — TUN and routes persist after the tunnel dies. Tool shows cleanup commands.

4. **proxychains socks4 vs socks5** — socks5 is what you want. Tool reminds you.

5. **Double-pivot agent transfer** — download the agent from the first pivot, not from attacker. The second host can't reach your VPN IP.

---

## When To Use What

| Method | Full TCP/UDP/ICMP | No Proxychains | No Binary Transfer | Simplest Setup |
|---|---|---|---|---|
| **Ligolo-ng** | ✓ | ✓ | ✗ | |
| **Chisel** | | | ✗ | |
| **SSH** | | | ✓ | |
| **sshuttle** | TCP only | ✓ | ✓ | ✓ |

---

## License

MIT
cd pivot-plumber
chmod +x pivot.py
sudo ln -s $(pwd)/pivot.py /usr/local/bin/pivot
```

---

## Usage

```bash
# Ligolo-ng full setup
pivot ligolo -a 10.10.15.110 -p 172.16.139.10 -n 172.16.139.0/24

# Ligolo with double pivot
pivot ligolo -a 10.10.15.110 -p 172.16.139.10 -n 172.16.139.0/24 --double --double-net 10.10.0.0/24

# Chisel SOCKS + port forward
pivot chisel -a 10.10.15.110 -p 10.10.10.5

# SSH tunnels
pivot ssh -p 10.10.10.5 -u developer

# sshuttle transparent proxy
pivot sshuttle -p 10.10.10.5 -u admin -n 10.0.0.0/24

# Full cheatsheet — all methods side by side
pivot cheatsheet

# Check your interfaces
pivot interfaces
```

---

## What Each Mode Gives You

### `pivot ligolo`
Step-by-step Ligolo-ng setup: TUN interface creation, route addition, proxy start, agent transfer (Linux + Windows), session selection, connectivity verification, and **callback guidance** (which IP to use for reverse shells from internal hosts). Includes double-pivot instructions with `--double`.

### `pivot chisel`
Chisel SOCKS proxy and port forward commands for both attacker and target. Includes agent transfer, proxychains config, and callback routing options.

### `pivot ssh`
Dynamic SOCKS proxy (`-D`), local port forward (`-L`), remote port forward (`-R`), and key-based variants. No binary transfer needed.

### `pivot sshuttle`
Transparent TCP routing — no proxychains needed. Single and multi-subnet, with exclusion rules.

### `pivot cheatsheet`
All four methods plus a comparison table and the **5 common gotchas** that have burned you before.

### `pivot interfaces`
Auto-detects your network interfaces and IPs — shows which one to use for target callbacks.

---

## Options

| Flag | Short | Description | Default |
|---|---|---|---|
| `--attacker-ip` | `-a` | Your attacker IP (tun0) | auto-detect |
| `--pivot-ip` | `-p` | Pivot host IP | — |
| `--internal-net` | `-n` | Internal subnet to reach | 172.16.0.0/24 |
| `--pivot-user` | `-u` | SSH user on pivot | user |
| `--listen-port` | | Listener port | varies |
| `--socks-port` | | SOCKS proxy port | 1080 |
| `--tun-name` | | Ligolo TUN name | ligolo |
| `--double` | | Include double-pivot guidance | off |
| `--double-net` | | Second internal network | 10.10.0.0/24 |

---

## The 5 Gotchas This Tool Prevents

1. **Listeners on the wrong IP** — internal hosts can't route to your tun0/VPN. The tool prints exactly which IP to use for callbacks.

2. **nmap through SOCKS** — must use `-sT` (connect scan), not `-sS` (SYN scan). SYN scans don't work through SOCKS proxies.

3. **Stale Ligolo interfaces** — TUN and routes persist after the tunnel dies. Tool shows cleanup commands.

4. **proxychains socks4 vs socks5** — socks5 is what you want. Tool reminds you.

5. **Double-pivot agent transfer** — download the agent from the first pivot, not from attacker. The second host can't reach your VPN IP.

---

## When To Use What

| Method | Full TCP/UDP/ICMP | No Proxychains | No Binary Transfer | Simplest Setup |
|---|---|---|---|---|
| **Ligolo-ng** | ✓ | ✓ | ✗ | |
| **Chisel** | | | ✗ | |
| **SSH** | | | ✓ | |
| **sshuttle** | TCP only | ✓ | ✓ | ✓ |

---

## License

MIT
