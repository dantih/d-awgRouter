#!/bin/bash
set -e

NAME="d-awg-router-web"
BIN_DEST="/usr/local/bin/$NAME"
PLIST_LABEL="com.d-awg-router.web"
PLIST_DEST="$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
CONFIG_DIR="$HOME/.d-awg-router"
SUDOERS_FILE="/etc/sudoers.d/d-awg-router"
USER="$(whoami)"

# Resolve real user (not root)
if [ "$USER" = "root" ] && [ -n "$SUDO_USER" ]; then
    USER="$SUDO_USER"
    HOME="/Users/$USER"
    PLIST_DEST="/Users/$USER/Library/LaunchAgents/$PLIST_LABEL.plist"
    CONFIG_DIR="/Users/$USER/.d-awg-router"
fi

REPO="dantih/d-awgRouter"
RELEASE_URL="https://github.com/$REPO/releases/latest/download/$NAME-darwin-arm64"

echo ""
echo "=============================="
echo "  d-awg-router-web Installer"
echo "=============================="
echo ""

# --- Step 1: cache sudo ---
echo "[1/6] Кэшируем sudo (потребуется пароль)..."
sudo -v || { echo "[✗] sudo недоступен"; exit 1; }

# Keep sudo alive in background
while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &

# --- Step 2: download binary ---
echo "[2/6] Скачиваем $NAME из GitHub Releases..."
TMP_BIN=$(mktemp)
if curl -sfL -o "$TMP_BIN" "$RELEASE_URL"; then
    chmod +x "$TMP_BIN"
    echo "  ✓ Скачан: $RELEASE_URL"
else
    echo "[✗] Не удалось скачать бинарник с $RELEASE_URL"
    echo "    Проверь: https://github.com/$REPO/releases"
    rm -f "$TMP_BIN"
    exit 1
fi

# --- Step 3: install binary ---
echo "[3/6] Устанавливаем $NAME → $BIN_DEST"
sudo cp "$TMP_BIN" "$BIN_DEST"
sudo chmod 755 "$BIN_DEST"
rm -f "$TMP_BIN"

# --- Step 4: sudoers ---
echo "[4/6] Настраиваем /etc/sudoers.d/d-awg-router"
WG_BIN=$(which wg 2>/dev/null || echo "/opt/homebrew/bin/wg")
WG_GO_BIN=$(which wireguard-go 2>/dev/null || echo "/opt/homebrew/bin/wireguard-go")
SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: $BIN_DEST, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /bin/pgrep, $WG_BIN, $WG_GO_BIN"
echo "$SUDOERS_LINE" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
echo "  ✓ Разрешены: awg, amneziawg-go, route, ifconfig, kill, rm, pgrep, wg, wireguard-go"

# --- Step 5: directory structure + icon ---
echo "[5/6] Создаём ~/.d-awg-router/{configs,cache,routes,state}"
mkdir -p "$CONFIG_DIR"/{configs,cache,routes,state}

# Download icon from GitHub
ICON_DST="$CONFIG_DIR/awg-icon.png"
ICON_URL="https://raw.githubusercontent.com/$REPO/main/assets/awg-icon-big.png"
if curl -sfL -o "$ICON_DST" "$ICON_URL"; then
    echo "  ✓ Иконка скачана"
fi

# Set icon on binary via fileicon
if [ -f "$ICON_DST" ]; then
    if command -v fileicon &>/dev/null; then
        echo "  ✓ Устанавливаем иконку на бинарник..."
        fileicon set "$BIN_DEST" "$ICON_DST" 2>/dev/null || true
    elif [ -x /opt/homebrew/bin/fileicon ]; then
        echo "  ✓ Устанавливаем иконку на бинарник..."
        /opt/homebrew/bin/fileicon set "$BIN_DEST" "$ICON_DST" 2>/dev/null || true
    fi
fi

# --- Step 6: launchd plist ---
echo "[6/6] Устанавливаем launchd plist → $PLIST_DEST"

cat > /tmp/com.d-awg-router.web.plist << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DEST</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$HOME</string>
    <key>StandardOutPath</key>
    <string>/tmp/$PLIST_LABEL.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/$PLIST_LABEL.err</string>
</dict>
</plist>
PLIST

cp /tmp/com.d-awg-router.web.plist "$PLIST_DEST"
chmod 644 "$PLIST_DEST"

# Unload existing if any
launchctl unload "$PLIST_DEST" 2>/dev/null || true
sleep 1

# Load
launchctl load "$PLIST_DEST"
sleep 2

# --- Verify ---
echo ""
echo "=============================="
echo "  Проверка"
echo "=============================="

if launchctl list | grep -q "$PLIST_LABEL"; then
    echo "[✓] launchd: запущен"
else
    echo "[✗] launchd: НЕ запущен!"
fi

if lsof -i -P -n 2>/dev/null | grep -q ":8765 (LISTEN)"; then
    echo "[✓] Веб-сервис: слушает на 127.0.0.1:8765"
else
    echo "[✗] Веб-сервис: НЕ слушает!"
    cat /tmp/$PLIST_LABEL.err 2>/dev/null
fi

# Quick functional test
echo ""
echo "--- Быстрый тест ---"
RESP=$(curl -sf http://127.0.0.1:8765/ 2>/dev/null | head -3)
if [ -n "$RESP" ]; then
    echo "[✓] HTTP 200 OK"
else
    echo "[✗] HTTP не отвечает"
fi

echo ""
echo "=============================="
echo "  Установка завершена! 🐱"
echo "=============================="
echo ""
echo "  Открой в браузере (или ssh -L):"
echo "    http://127.0.0.1:8765"
echo ""
echo "  Команды управления:"
echo "    launchctl unload  $PLIST_DEST  # остановить"
echo "    launchctl load    $PLIST_DEST  # запустить"
echo "    tail -f /tmp/$PLIST_LABEL.log  # логи"
echo ""
