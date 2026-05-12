# d-awgRouter

> **🌐 [Русская версия](README.md) | English version ↓**

**d-awgRouter** — a web service for managing **WireGuard / AmneziaWG VPN** on macOS: config management, dynamic route selection from GitHub (RockBlack-VPN/ip-address), interface control.

Automatically detects config type — regular WireGuard or AmneziaWG — by checking for `Jc`/`Jmin`/`Jmax` parameters.

Supports multiple configurations, multi-language UI (EN / RU), clean web interface.

## How it works

```
user → web interface (127.0.0.1:8765) → Go binary (sudo -n)
                                       ├── AmneziaWG: awg + amneziawg-go
                                       └── WireGuard: wg + wireguard-go
```

Routes (CIDR subnets) for various services (Telegram, YouTube, Netflix, etc.) are fetched from [RockBlack-VPN/ip-address](https://github.com/RockBlack-VPN/ip-address). Pick the ones you need — they get added to the VPN interface.

## Directory structure

```
~/.d-awg-router/
├── configs/*.conf            # all saved WireGuard/AWG configs
├── active                    # active config name
├── cache/<Service>.cidr      # cached CIDRs (one file per service)
├── routes/<Service>          # empty file = service enabled
├── state/current             # state (interface, IP)
├── lang                      # selected language (en / ru)
└── awg-icon.png              # service icon
```

## Quick start

### Install from release

```bash
curl -sfL -o /tmp/d-awg-router-web https://github.com/dantih/d-awgRouter/releases/latest/download/d-awg-router-web-darwin-arm64
chmod +x /tmp/d-awg-router-web
echo "YOUR_PASSWORD" | sudo -S mv /tmp/d-awg-router-web /usr/local/bin/d-awg-router-web
```

### Or via install.sh

```bash
curl -sfL https://raw.githubusercontent.com/dantih/d-awgRouter/main/install/install.sh | bash
```

### launchd setup

```bash
mkdir -p ~/Library/LaunchAgents

cat > ~/Library/LaunchAgents/com.d-awg-router.web.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.d-awg-router.web</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/d-awg-router-web</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Users/$(whoami)</string>
    <key>StandardOutPath</key>
    <string>/tmp/com.d-awg-router.web.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/com.d-awg-router.web.err</string>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.d-awg-router.web.plist
```

### Usage

```bash
# Open in browser (via SSH tunnel)
ssh -L 8765:127.0.0.1:8765 mac

# In browser:
# 1. Config → paste WireGuard or AmneziaWG config → Save
# 2. Config → Activate (to make it active)
# 3. Services → select needed ones (Telegram, YouTube, ...) → Save Selection
# 4. Control → UP
```

## Web interface

Three tabs:

| Tab | Purpose |
|-----|---------|
| **Control** | UP / DOWN / Restart VPN, status & routes view |
| **Services** | Select CIDR services to route through VPN |
| **Config** | Config list, editor, create/delete/activate |

Language selector in the header (English / Русский).

## Requirements

### For AmneziaWG
- macOS (Apple Silicon)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) binary
- [awg](https://github.com/amnezia-vpn/amneziawg-tools) (amneziawg-tools)

### For regular WireGuard
- [wireguard-go](https://www.wireguard.com/) — `brew install wireguard-go`
- [wireguard-tools](https://www.wireguard.com/) — `brew install wireguard-tools`

`wg` and `wireguard-go` binaries must be in PATH (or in `/opt/homebrew/bin/`).

### sudoers

After installation, add to `/etc/sudoers.d/d-awg-router`:

```
YOUR_USER ALL=(ALL) NOPASSWD: /usr/local/bin/d-awg-router-web, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /bin/pgrep, /opt/homebrew/bin/wg, /opt/homebrew/bin/wireguard-go
```

Or use [install.sh](/install/install.sh) — it creates sudoers automatically.

## Build

```bash
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o d-awg-router-web-darwin-arm64 ./cmd/d-awg-router-web/
```

## Config detection

The system automatically detects config type:

| Flag | AmneziaWG | WireGuard |
|------|-----------|-----------|
| `Jc` | ✅ yes | ❌ no |
| `Jmin` | ✅ yes | ❌ no |
| `Jmax` | ✅ yes | ❌ no |
| Backend | `amneziawg-go` | `wireguard-go` |
| Tools | `awg` | `wg` |

## Internationalization

Language strings are in `cmd/d-awg-router-web/lang.go`. To add a new language:

1. Add a block to `langData`:
```go
"fr": LangMap{
    "btn.up": "MONTER",
    "btn.down": "BAISSER",
    // ...
},
```
2. Update the HTML selector (add `<option value="fr">Français</option>`)
3. Rebuild

IP addresses, interface names and raw config content — always in English.

## Security

- Service listens only on `127.0.0.1:8765` (local access only)
- All admin access via SSH tunnel or locally
- `sudo -n` via strict `/etc/sudoers.d/d-awg-router` (whitelisted commands only)
- WireGuard private keys stored in `~/.d-awg-router/configs/` with 0600 permissions
- VPN configs are never stored in git history
