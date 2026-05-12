#!/bin/bash
set -e

NAME="d-awg-router-web"
BIN="$NAME"
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

echo ""
echo "=============================="
echo "  d-awg-router-web Installer"
echo "=============================="
echo ""

# --- Check arguments ---
if [ ! -f "$BIN" ]; then
    echo "[✗] Бинарь '$BIN' не найден в текущей папке."
    echo "    Сначала скопируй сюда: scp d-awg-router-web-darwin-arm64 mac:$BIN"
    exit 1
fi

# --- Step 1: cache sudo ---
echo "[1/5] Кэшируем sudo (потребуется пароль)..."
sudo -v || { echo "[✗] sudo недоступен"; exit 1; }

# Keep sudo alive in background
while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &

# --- Step 2: install binary ---
echo "[2/5] Устанавливаем $NAME → $BIN_DEST"
sudo cp "$BIN" "$BIN_DEST"
sudo chmod 755 "$BIN_DEST"

# --- Step 3: sudoers ---
echo "[3/5] Настраиваем /etc/sudoers.d/d-awg-router"
# Ищем wg и wireguard-go
WG_BIN=$(which wg 2>/dev/null || echo "/opt/homebrew/bin/wg")
WG_GO_BIN=$(which wireguard-go 2>/dev/null || echo "/opt/homebrew/bin/wireguard-go")
SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: $BIN_DEST, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /bin/pgrep, $WG_BIN, $WG_GO_BIN"
echo "$SUDOERS_LINE" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
echo "  ✓ Разрешены: awg, amneziawg-go, route, ifconfig, kill, rm, pgrep, wg, wireguard-go"

# --- Step 4: directory structure + icon ---
echo "[4/5] Создаём ~/.d-awg-router/{configs,cache,routes,state}"
mkdir -p "$CONFIG_DIR"/{configs,cache,routes,state}

# Copy icon if present
ICON_SRC="assets/icon.png"
ICON_DST="$CONFIG_DIR/awg-icon.png"
if [ -f "$ICON_SRC" ]; then
    cp "$ICON_SRC" "$ICON_DST"
    echo "  ✓ Иконка скопирована"
elif [ -f "awg-icon.png" ]; then
    cp "awg-icon.png" "$ICON_DST"
    echo "  ✓ Иконка скопирована"
fi

# --- Step 5: launchd plist ---
echo "[5/5] Устанавливаем launchd plist → $PLIST_DEST"

ICON_PLIST=""
if [ -f "$CONFIG_DIR/awg-icon.png" ]; then
    ICON_PLIST="    <key>Nice</key>
    <integer>0</integer>
    <key>LSUIElement</key>
    <true/>
    <key>CFBundleIconFile</key>
    <string>$CONFIG_DIR/awg-icon.png</string>
"
fi

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
${ICON_PLIST:-}</dict>
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
