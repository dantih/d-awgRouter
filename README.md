# d-awgRouter

> 🌐 **[Русский](README.ru.md)** | **English** ↓

**d-awgRouter** — a web service for managing **WireGuard / AmneziaWG VPN** on macOS:
config management, dynamic route selection from GitHub (RockBlack-VPN/ip-address),
interface UP/DOWN, and **Full Tunnel** mode (route all traffic through VPN via System Configuration).

Automatically detects config type — regular WireGuard or AmneziaWG — by checking for
`Jc`/`Jmin`/`Jmax` parameters.

Supports multiple configurations, multi-language UI (EN / RU), debug mode, sudoers auto-setup.

## How it works

```
user → web interface (127.0.0.1:8765) → Go binary (sudo -n)
                                       ├── AmneziaWG: awg + amneziawg-go
                                       └── WireGuard: wg + wireguard-go
```

Routes (CIDR subnets) for various services (Telegram, YouTube, Netflix, etc.) are fetched
from [RockBlack-VPN/ip-address](https://github.com/RockBlack-VPN/ip-address).
Pick the ones you need — they get routed through the VPN interface.

## Features

- **Split tunneling** — route only selected services through VPN
- **Full Tunnel** — route ALL traffic through VPN (scutil System Configuration)
- **Multiple configs** — save, switch, edit several WireGuard/AmneziaWG configs
- **Auto-detect** — detects WireGuard vs AmneziaWG from config parameters
- **Debug mode** — detailed logging to `/tmp/com.d-awg-router.web.log`
- **Web UI** — clean interface with Control / Services / Config tabs
- **Multilingual** — English and Russian built-in
- **Service management** — launchd integration, `start`/`stop`/`restart`/`status` CLI

## Directory structure

```
~/.d-awg-router/
├── configs/*.conf        # saved WireGuard/AWG configs (managed via web UI)
├── active                # active config name
├── cache/<Service>.cidr  # cached CIDRs (one file per service)
├── routes/<Service>      # empty file = service enabled
├── state/
│   ├── current           # current interface name and IP
│   ├── ft_exclude        # exclude routes for Full Tunnel (one CIDR per line)
│   ├── ft_service_uuid   # scutil service UUID for Full Tunnel
│   ├── full_tunnel       # "true" if Full Tunnel is enabled
│   ├── orig_default_gw   # original default gateway (for Full Tunnel excludes)
│   ├── wg_pid            # PID of wireguard-go/amneziawg-go process
│   └── debug             # exists = debug mode enabled (touch to enable)
├── lang                  # selected language (en / ru)
└── awg-icon.png          # service icon
```

## Quick start

### Download binary

```bash
# Latest release
curl -sfL -o /tmp/d-awg-router-web https://github.com/dantih/d-awgRouter/releases/latest/download/d-awg-router-web-darwin-arm64
chmod +x /tmp/d-awg-router-web
mkdir -p ~/.d-awg-router
mv /tmp/d-awg-router-web ~/.d-awg-router/d-awg-router-web
```

### Or via install.sh

```bash
curl -sfL https://raw.githubusercontent.com/dantih/d-awgRouter/main/install.sh | bash
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
        <string>/Users/$(whoami)/.d-awg-router/d-awg-router-web</string>
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

### sudoers

`install.sh` creates sudoers automatically. If doing it manually:

```
# /etc/sudoers.d/d-awg-router
YOUR_USER ALL=(ALL) NOPASSWD: /Users/YOUR_USER/.d-awg-router/d-awg-router-web, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /opt/homebrew/bin/wg, /opt/homebrew/bin/wireguard-go, /usr/sbin/scutil
```

## CLI commands

```bash
# Manage the web service via launchd
~/.d-awg-router/d-awg-router-web start
~/.d-awg-router/d-awg-router-web stop
~/.d-awg-router/d-awg-router-web restart

# Show service status (PID, VPN interface, config, routes)
~/.d-awg-router/d-awg-router-web status

# Toggle debug mode (creates or removes state/debug marker file)
~/.d-awg-router/d-awg-router-web debug on
~/.d-awg-router/d-awg-router-web debug off

# Manually destroy a utun interface (⚠️ use with caution)
~/.d-awg-router/d-awg-router-web destroy utun7
```

## Usage

```bash
# Open web interface (browser or via SSH tunnel)
ssh -L 8765:127.0.0.1:8765 mac
# Then open http://127.0.0.1:8765
```

### Steps

1. **Config tab** → paste WireGuard or AmneziaWG config → Save
2. **Config tab** → click Activate on your config
3. **Services tab** → select needed services (Telegram, YouTube, ...) → Save Selection
4. **Control tab** → click UP

## Full Tunnel mode

> Routes **all** traffic through the VPN interface using macOS System Configuration (scutil).

### How it works

1. When enabled via the **Full Tunnel** toggle on the Control tab, `reloadFTEnabled()` is called
2. A new Network Service is registered in System Configuration via `scutil`
3. This service is marked as Primary with highest priority
4. **Exclude routes** are added for:
   - The original (non-VPN) subnet (so LAN access is preserved)
   - The VPN endpoint IP (so the VPN connection itself doesn't break)
   - SSH client subnet (if detectable — prevents SSH lockout)
   - Link-local `169.254.0.0/16`
5. The exclude routes are saved to `state/ft_exclude` for cleanup on disable
6. When disabled, the scutil service is removed and exclude routes are deleted

### When it activates

- **At UP** — if Full Tunnel was previously enabled, it auto-registers after the interface comes up
- **On toggle** — switching the Full Tunnel checkbox on the web UI triggers register/unregister immediately

### Auto-enable at startup

If `state/full_tunnel` contains `true` before UP, Full Tunnel is automatically applied
after the interface is up (WireGuard or AmneziaWG). No manual toggle needed.

## Web interface

Four functional tabs:

| Tab | Purpose |
|-----|---------|
| **Control** | UP / DOWN / Restart VPN, Full Tunnel toggle, status & route view |
| **Services** | Select CIDR services to route through VPN, Force Routes button |
| **Config** | Config list, view/edit, create, delete, activate |
| **About** | Version info, changelog, build info |

Language selector in the header (English / Русский).

## Debug mode

Enable for detailed logging to `/tmp/com.d-awg-router.web.log`:

```bash
# Via CLI
~/.d-awg-router/d-awg-router-web debug on
# Then restart: ~/.d-awg-router/d-awg-router-web restart

# Or manually
touch ~/.d-awg-router/state/debug
# Then restart the service

# Watch logs in real time
tail -f /tmp/com.d-awg-router.web.log
```

When debug is active, every operation logs its step: interface detection,
PID management, scutil registration, route commands.

## Requirements

### For AmneziaWG
- macOS (Apple Silicon)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) binary
- [awg](https://github.com/amnezia-vpn/amneziawg-tools) (amneziawg-tools)

### For regular WireGuard
- `brew install wireguard-go`
- `brew install wireguard-tools`

Binaries must be in PATH or in `/opt/homebrew/bin/`.

## Config detection

The system automatically detects config type:

| Flag | AmneziaWG | WireGuard |
|------|-----------|-----------|
| `Jc` | ✅ present | ❌ absent |
| `Jmin` | ✅ present | ❌ absent |
| `Jmax` | ✅ present | ❌ absent |
| Backend | `amneziawg-go` | `wireguard-go` |
| Tools | `awg` | `wg` |

## Internationalization

Language strings are in `cmd/d-awg-router-web/lang.go`. To add a new language:

1. Add a block to `langData`:
```go
"fr": LangMap{
    "btn.up": "MONTER",
    // ...
},
```
2. Update the HTML selector (`<option value="fr">Français</option>`)
3. Rebuild

IP addresses, interface names, and raw config content are always in English.

## Build

```bash
# From source
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o d-awg-router-web ./cmd/d-awg-router-web/

# Development (debug symbols kept, useful for crash analysis)
GOOS=darwin GOARCH=arm64 go build -o d-awg-router-web ./cmd/d-awg-router-web/
```

## Security

- Service listens only on `127.0.0.1:8765` (local access only)
- All admin access via SSH tunnel or locally
- `sudo -n` via strict `/etc/sudoers.d/d-awg-router` (whitelisted commands only)
- WireGuard private keys stored in `~/.d-awg-router/configs/` with 0600 permissions
- VPN configs are never stored in git history
