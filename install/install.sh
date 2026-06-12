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
GO_BIN="go"

echo ""
echo "=============================="
echo "  d-awg-router-web Installer"
echo "=============================="
echo ""

# --- Step 0: check dependencies ---
echo "[0/7] Проверяем зависимости..."

BREW_BIN="/opt/homebrew/bin/brew"
NEED_BREW=""

find_bin() {
    local name="$1"
    local paths="$2"
    for p in $paths; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    command -v "$name" 2>/dev/null
}

check_dep() {
    local name="$1"
    local brew_pkg="$2"
    local paths="$3"
    local found=$(find_bin "$name" "$paths")
    if [ -n "$found" ]; then
        echo "  ✓ $name: $found"
        return 0
    fi
    echo "  ⚠ $name не найден"
    if [ -n "$brew_pkg" ]; then
        NEED_BREW="$NEED_BREW $brew_pkg"
    fi
}

check_dep "wg" "wireguard-tools" "/opt/homebrew/bin/wg /usr/local/bin/wg"
check_dep "wireguard-go" "" "/opt/homebrew/bin/wireguard-go /usr/local/bin/wireguard-go"
check_dep "awg" "" "/usr/local/bin/awg"
check_dep "amneziawg-go" "" "/usr/local/bin/amneziawg-go"

# Go (для сборки) — если нет, установим через brew
if ! command -v go &>/dev/null; then
    echo "  ⚠ go не найден"
    GO_BIN="/opt/homebrew/bin/go"
    NEED_BREW="$NEED_BREW go"
else
    GO_BIN=$(command -v go)
    echo "  ✓ go: $GO_BIN"
fi

# Install missing brew packages
if [ -n "$NEED_BREW" ]; then
    echo ""
    echo "  Не хватает: $NEED_BREW"
    if [ -x "$BREW_BIN" ]; then
        INSTALL=false
        if [ -t 0 ]; then
            echo -n "  Установить через Homebrew? [Y/n] "
            read -r answer
            case "$answer" in
                ""|y|Y|yes) INSTALL=true ;;
                *) echo "  ⚠ Пропускаем." ;;
            esac
        else
            echo "  Устанавливаю (curl | bash)..."
            INSTALL=true
        fi
        if [ "$INSTALL" = true ]; then
            eval "$($BREW_BIN shellenv)"
            for pkg in $NEED_BREW; do
                echo -n "  → brew install $pkg... "
                if brew install "$pkg"; then
                    echo "✓"
                    # Re-check paths after install
                    WG_CHECK=$(ls /opt/homebrew/bin/wg /opt/homebrew/bin/wireguard-go /usr/local/bin/wg 2>/dev/null || true)
                else
                    echo "✗"
                fi
            done
        fi
    else
        echo "  ⚠ Homebrew не найден. Установи вручную:"
        for pkg in $NEED_BREW; do
            echo "    brew install $pkg"
        done
    fi
    echo ""
fi

# --- Step 1: cache sudo ---
echo "[1/7] Кэшируем sudo (потребуется пароль)..."
sudo -v
# --- Step 2: clone source ---
echo "[2/7] Клонируем исходники $REPO..."
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo -n "  ⏳ git clone... "
# shallow clone for speed
if git clone --depth 1 "https://github.com/$REPO.git" "$TMP_DIR" 2>/dev/null; then
    echo "✓"
    cd "$TMP_DIR"
else
    echo "✗"
    echo "[✗] Не удалось склонировать репозиторий."
    exit 1
fi

# --- Step 3: build from source ---
echo "[3/7] Собираем $NAME из исходников..."
echo -n "  ⏳ $GO_BIN build... "
if $GO_BIN build -ldflags="-s -w" -o "/tmp/$NAME" "./cmd/$NAME/" 2>/tmp/dawg_build_err; then
    SIZE=$(du -h "/tmp/$NAME" | cut -f1)
    echo "✓ $SIZE"
else
    echo "✗"
    echo "[✗] Ошибка сборки:"
    cat /tmp/dawg_build_err
    exit 1
fi

# Save version from repo
VERSION=$(cat version.txt 2>/dev/null || echo "dev")
echo -n "  ⏳ Версия... "
echo "$VERSION" > "$CONFIG_DIR/version.txt"
echo "✓ $VERSION"

# --- Step 4: install binary ---
echo "[4/7] Устанавливаем $NAME → $BIN_DEST"
sudo cp "/tmp/$NAME" "$BIN_DEST"
sudo chmod 755 "$BIN_DEST"
rm -f "/tmp/$NAME"

# Clean up Git repo (delete source)
rm -rf "$TMP_DIR"
trap - EXIT

# --- Step 5: sudoers ---
echo "[5/7] Настраиваем /etc/sudoers.d/d-awg-router"
WG_BIN=$(which wg 2>/dev/null || echo "/opt/homebrew/bin/wg")
WG_GO_BIN=$(which wireguard-go 2>/dev/null || echo "/opt/homebrew/bin/wireguard-go")
SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: $BIN_DEST, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /bin/pgrep, $WG_BIN, $WG_GO_BIN"
echo "$SUDOERS_LINE" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
echo "  ✓ Разрешены: awg, amneziawg-go, route, ifconfig, kill, rm, pgrep, wg, wireguard-go"

# --- Step 6: directory structure + icon ---
echo "[6/7] Создаём ~/.d-awg-router/{configs,cache,routes,state}"
mkdir -p "$CONFIG_DIR"/{configs,cache,routes,state}

# Download icon from GitHub
ICON_DST="$CONFIG_DIR/awg-icon.png"
ICON_URL="https://raw.githubusercontent.com/$REPO/main/assets/awg-icon-big.png"
echo -n "  ⏳ Иконка... "
if curl -sfL -o "$ICON_DST" "$ICON_URL"; then
    echo "✓"
else
    echo "— (не критично)"
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

# --- Step 7: launchd plist ---
echo "[7/7] Устанавливаем launchd plist → $PLIST_DEST"

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
